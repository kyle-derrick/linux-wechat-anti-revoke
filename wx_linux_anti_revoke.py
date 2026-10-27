#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wx_linux_anti_revoke.py — Linux 微信 4.x 防撤回一键补丁（纯标准库，零依赖）

原理（参考 RevokeMsgPatcher 的“让撤回分支永不执行”思想，适配微信 4.x）：
  微信 4.x 主程序 /opt/wechat/wechat（stripped PIE ELF）里有一张消息字段名池，
  撤回同步消息的解析代码用 `lea reg,[rip+X]` 引用池中的明文键 "revokemsg" 来
  识别撤回指令。本脚本把池中的 "revokemsg" 原地改写成等长乱串（如 "revokemsq"），
  使撤回键永远匹配失败 -> 撤回指令被当作未知消息忽略 -> 原消息保留。
  * 不改任何机器码，不动函数入口，恢复备份即完全还原。
  * 自己发的消息撤回不受影响（那是主动 API 调用，走另一条路径）。

策略:
  corrupt-key  (默认, 自动) 改写字段名池中被代码引用的 revokemsg 键
  nop-calls    (进阶, 需 --func VA) NOP 掉所有对指定函数的直接调用 (E8->5x90)
  ret0         (进阶, 需 --func VA) 函数入口写 xor eax,eax; ret

用法:
  sudo python3 wx_linux_anti_revoke.py analyze            # 只分析, 不改字节
  sudo python3 wx_linux_anti_revoke.py patch              # 备份并打补丁
  sudo python3 wx_linux_anti_revoke.py patch --dry-run    # 只看补丁计划
  sudo python3 wx_linux_anti_revoke.py patch --strategy nop-calls --func 0x1234abc
  sudo python3 wx_linux_anti_revoke.py restore            # 还原
  sudo python3 wx_linux_anti_revoke.py status             # 状态

适用目标: deb/rpm 安装 (/usr/bin/wechat 或 /opt/wechat/wechat);
          AppImage 用 --appimage 路径 (自动解包打补丁并生成启动器)。

仅用于个人设备上的技术研究与学习。修改客户端可能违反腾讯服务条款, 风险自负。
"""

import argparse
import hashlib
import os
import re
import shutil
import stat
import struct
import subprocess
import sys

# ---------------------------------------------------------------- 常量

ANCHORS = [
    # (标签, 字节串, 说明)
    ("revokemsg", b"revokemsg", "撤回指令键 (默认补丁目标)"),
    ("revoketime", b"revoketime", "撤回时间字段"),
    ("revoke_msg", b"revoke_msg", "sysmsg 撤回模板名"),
    ("sysmsgtemplate", b"sysmsgtemplate", "系统消息模板容器"),
    ("replacemsg", b"replacemsg", "撤回替换提示 XML 键"),
    ("newmsgid", b"newmsgid", "消息 id 字段"),
    ("svrid", b"svrid", "服务端消息 id 字段"),
]

EXTRA_PROBES = ["撤回了", "重新编辑", "消息已被撤回", "引用内容已撤回"]

# 本脚本作者于 2026-10-26 实测验证过的官方构建 (WeChatLinux deb)
VERIFIED_BUILDID = "d62bde21b26c5928e7dea826271e21a542b755b5"

LEA_RE = re.compile(rb"[\x48-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
CALL_RE = re.compile(rb"\xe8", re.S)
MANGLE_LAST = {ord("g"): ord("q")}  # revokemsg -> revokemsq


def mangle(needle):
    """把锚点串变成等长、几乎不可能出现的乱串 (可读性保留便于识别)"""
    out = bytearray(needle)
    if out and out[-1] in MANGLE_LAST:
        out[-1] = MANGLE_LAST[out[-1]]
    else:  # 兜底: 末字节取反高位
        out[-1] ^= 0x20
    return bytes(out)


# ---------------------------------------------------------------- ELF 解析

class Elf:
    def __init__(self, path):
        self.path = path
        self.data = bytearray(open(path, "rb").read())
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            raise SystemExit("不是 x86_64 小端 ELF: %s" % path)
        (self.e_type, self.e_machine) = struct.unpack_from("<HH", d, 16)
        (self.e_phoff,) = struct.unpack_from("<Q", d, 0x20)
        (self.e_shoff,) = struct.unpack_from("<Q", d, 0x28)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", d, 0x36)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", d, 0x3A)
        self.segments = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            p_type, p_flags = struct.unpack_from("<II", d, o)
            p_offset, p_vaddr = struct.unpack_from("<QQ", d, o + 8)
            p_filesz = struct.unpack_from("<Q", d, o + 0x20)[0]
            if p_type == 1:
                self.segments.append({"off": p_offset, "va": p_vaddr,
                                      "size": p_filesz, "exec": bool(p_flags & 1)})
        self.sections = []
        if self.e_shoff and self.e_shnum:
            (e_shstrndx,) = struct.unpack_from("<H", d, 0x3E)
            so = self.e_shoff + e_shstrndx * self.e_shentsize
            strtab_off = struct.unpack_from("<Q", d, so + 0x18)[0]
            for i in range(self.e_shnum):
                o = self.e_shoff + i * self.e_shentsize
                (sh_name,) = struct.unpack_from("<I", d, o)
                sh_type, sh_flags = struct.unpack_from("<II", d, o + 4)
                sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", d, o + 0x10)
                name = self.cstr(strtab_off + sh_name).decode("utf-8", "replace")
                self.sections.append({"name": name, "type": sh_type,
                                      "flags": sh_flags, "va": sh_addr,
                                      "off": sh_offset, "size": sh_size})

    def cstr(self, off, maxlen=256):
        end = self.data.find(b"\x00", off)
        if end < 0 or end > off + maxlen:
            end = min(off + maxlen, len(self.data))
        return bytes(self.data[off:end])

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

    def build_id(self):
        n = self.section(".note.gnu.build-id")
        if not n:
            return None
        blob = bytes(self.data[n["off"]:n["off"] + n["size"]])
        i = blob.find(b"GNU\x00")
        if i < 0:
            return None
        return blob[i + 4:i + 4 + 20].hex()

    def off2va(self, off):
        for s in self.sections:
            if s["va"] and s["size"] and s["off"] <= off < s["off"] + s["size"]:
                return s["va"] + (off - s["off"])
        for seg in self.segments:
            if seg["off"] <= off < seg["off"] + seg["size"]:
                return seg["va"] + (off - seg["off"])
        return None

    def va2off(self, va):
        for s in self.sections:
            if s["va"] and s["size"] and s["va"] <= va < s["va"] + s["size"]:
                return s["off"] + (va - s["va"])
        for seg in self.segments:
            if seg["va"] <= va < seg["va"] + seg["size"]:
                return seg["off"] + (va - seg["va"])
        return None

    def exec_span(self):
        t = self.section(".text")
        if t and t["size"]:
            return (t["off"], t["va"], t["size"])
        for seg in self.segments:
            if seg["exec"] and seg["size"] > 0x10000:
                return (seg["off"], seg["va"], seg["size"])
        raise SystemExit("找不到可执行段")


# ---------------------------------------------------------------- 扫描

def find_all(data, needle):
    out, i = [], data.find(needle)
    while i >= 0:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def lea_xref_map(elf, target_vas):
    """单遍扫描可执行段, 返回 {目标VA: [lea指令文件偏移]}"""
    off, va, size = elf.exec_span()
    blob = bytes(elf.data[off:off + size])
    want = set(target_vas)
    hits = {t: [] for t in want}
    for m in LEA_RE.finditer(blob):
        p = m.start()
        (disp,) = struct.unpack_from("<i", blob, p + 3)
        t = va + p + 7 + disp
        if t in want:
            hits[t].append(off + p)
    return hits


def call_sites_to(elf, target_va):
    off, va, size = elf.exec_span()
    blob = bytes(elf.data[off:off + size])
    sites = []
    for m in CALL_RE.finditer(blob):
        p = m.start()
        (disp,) = struct.unpack_from("<i", blob, p + 1)
        if va + p + 5 + disp == target_va:
            sites.append(off + p)
    return sites


# ---------------------------------------------------------------- 安装定位

def find_wechat_binary():
    for c in ("/usr/bin/wechat", "/opt/wechat/wechat",
              "/usr/local/bin/wechat", os.path.expanduser("~/.local/bin/wechat")):
        real = os.path.realpath(c)
        if os.path.isfile(real):
            return real
    return None


def appimage_extract(appimage_path):
    out_dir = os.path.join(os.path.dirname(os.path.abspath(appimage_path)),
                           "wx_patched")
    os.makedirs(out_dir, exist_ok=True)
    subprocess.run([appimage_path, "--appimage-extract"], cwd=out_dir,
                   check=True, stdout=subprocess.DEVNULL)
    root = os.path.join(out_dir, "squashfs-root")
    for dirpath, _dirs, files in os.walk(root):
        if "wechat" in files:
            p = os.path.join(dirpath, "wechat")
            if os.path.getsize(p) > 50 * 1024 * 1024:
                return p, out_dir
    raise SystemExit("AppImage 解包后未找到 wechat 主程序")


# ---------------------------------------------------------------- 分析

def analyze(elf, verbose=True):
    data = elf.data
    hits_by_tag = {}
    for tag, needle, desc in ANCHORS:
        occ = find_all(data, needle)
        hits_by_tag[tag] = occ

    # 收集所有出现位置的 VA, 一次性建 xref 表
    vas = {}
    for tag, occs in hits_by_tag.items():
        for o in occs:
            va = elf.off2va(o)
            if va is not None:
                vas[va] = (tag, o)
    xmap = lea_xref_map(elf, set(vas))

    if verbose:
        bid = elf.build_id()
        print("=" * 76)
        print("ELF   : %s  (%.1f MB, %s)" % (elf.path, len(data) / 1048576.0,
                                             "PIE" if elf.e_type == 3 else "EXEC"))
        print("BUILD : %s%s" % (bid, "" if bid != VERIFIED_BUILDID
                                else "  <- 本脚本实测验证过的构建"))
        if bid and bid != VERIFIED_BUILDID:
            print("注意  : 构建与已验证版本不同, 补丁结果请先 analyze + dry-run 人工确认")
        print("=" * 76)
        for tag, needle, desc in ANCHORS:
            occ = hits_by_tag[tag]
            print("[%s] %-15s x%-3d %s" % ("锚点" if occ else "缺失",
                                           tag, len(occ), desc))
        print()
        print("---- 代码交叉引用 (LEA rip 相对, 指向锚点串) ----")
        for va, sites in sorted(xmap.items()):
            if not sites:
                continue
            tag, o = vas[va]
            print("%-15s str@0x%-9x va=0x%-9x  xref=%d: %s"
                  % (tag, o, va, len(sites),
                     " ".join("0x%x" % s for s in sites[:6])))
        # 附加 UI 串情报
        print()
        print("---- UI 串情报 (仅参考, 通常无直接 xref) ----")
        for probe in EXTRA_PROBES:
            occ = find_all(data, probe.encode())
            if occ:
                print("%-12s x%d  @ %s" % (probe, len(occ),
                      " ".join("0x%x" % x for x in occ[:4])))
    return {"occ": hits_by_tag, "xmap": xmap, "vas": vas}


# ---------------------------------------------------------------- 补丁计划

def plan_corrupt_key(elf, rep):
    """默认策略: 改写“被代码引用”的 revokemsg 键; 返回 [(kind, off, size, orig, new, note)]"""
    edits = []
    for va, sites in sorted(rep["xmap"].items()):
        if not sites:
            continue
        tag, o = rep["vas"][va]
        if tag != "revokemsg":
            continue  # 只动撤回键; 其他锚点仅供分析
        needle = dict((t, n) for t, n, _d in ANCHORS)["revokemsg"]
        edits.append(("corrupt-key", o, len(needle),
                      bytes(elf.data[o:o + len(needle)]), mangle(needle),
                      "xref=%d @ %s" % (len(sites), " ".join(hex(s) for s in sites[:3]))))
    return edits


def plan_for_func(elf, strategy, func_va):
    fo = elf.va2off(func_va)
    if fo is None:
        raise SystemExit("--func VA 不在文件映射内: %s" % hex(func_va))
    if strategy == "ret0":
        return [("ret0", fo, 3, bytes(elf.data[fo:fo + 3]),
                 b"\x31\xc0\xc3", "func %s 入口" % hex(func_va))]
    sites = call_sites_to(elf, func_va)
    if not sites:
        raise SystemExit("全程序没有直接 call 到 %s (可能是间接调用), 无法 nop-calls"
                         % hex(func_va))
    return [("nop-call", s, 5, bytes(elf.data[s:s + 5]), b"\x90" * 5,
             "call -> %s" % hex(func_va)) for s in sites]


def show_plan(edits):
    for (kind, off, size, orig, new, note) in edits:
        print("  %-11s @0x%-9x  %s -> %s   (%s)"
              % (kind, off, orig.hex(), new.hex(), note))


def apply_edits(elf, edits):
    for (_k, off, size, orig, new, _n) in edits:
        if bytes(elf.data[off:off + size]) != orig:
            raise SystemExit("0x%x 处字节与预期不符(已打补丁或版本变化), 中止; "
                             "可先 restore" % off)
        elf.data[off:off + size] = new
    return len(edits)


# ---------------------------------------------------------------- 命令

def load_target(args):
    if getattr(args, "file", None):
        return os.path.realpath(args.file), None
    if getattr(args, "appimage", None):
        p, out_dir = appimage_extract(args.appimage)
        print("AppImage 已解包: %s" % p)
        return p, out_dir
    p = find_wechat_binary()
    if not p:
        raise SystemExit("未找到微信主程序; 用 -f 或 --appimage 指定")
    return p, None


def backup_path(target):
    return target + ".wxrevoke.bak"


def ensure_verified(elf, assume_yes=False):
    bid = elf.build_id()
    if bid == VERIFIED_BUILDID:
        return
    print("警告: 当前构建 build-id=%s 与已验证构建不同, 补丁逻辑可能不适用。" % bid)
    if not assume_yes:
        ans = input("仍要继续吗? [y/N] ").strip().lower()
        if ans != "y":
            raise SystemExit("已取消。")


def cmd_analyze(args):
    target, _ = load_target(args)
    analyze(Elf(target))
    print("\n下一步: patch --dry-run 预览补丁计划; 确认后 patch 正式写入。")


def cmd_patch(args):
    target, out_dir = load_target(args)
    elf = Elf(target)
    ensure_verified(elf, assume_yes=args.yes)
    rep = analyze(elf, verbose=False)

    if args.strategy == "corrupt-key":
        edits = plan_corrupt_key(elf, rep)
    else:
        if not args.func:
            raise SystemExit("策略 %s 需要 --func 0xVA (用 analyze 的 xref 输出配合 "
                             "Ghidra/objdump 找函数入口)" % args.strategy)
        edits = plan_for_func(elf, args.strategy, int(args.func, 0))
    if not edits:
        raise SystemExit("没有可补丁位置(锚点缺失或无代码引用), 请先 analyze。")

    print("补丁计划 (%s), 共 %d 处:" % (args.strategy, len(edits)))
    show_plan(edits)
    if args.dry_run:
        print("dry-run: 未写入任何字节。")
        return

    bak = backup_path(target)
    if os.path.exists(bak):
        print("备份已存在, 不覆盖: %s" % bak)
    else:
        shutil.copy2(target, bak)
        print("已备份 -> %s" % bak)
    n = apply_edits(elf, edits)
    tmp = target + ".tmp"
    open(tmp, "wb").write(elf.data)
    # 保留原文件的权限位与属主 (open 新建的 tmp 只有 umask 默认权限, 会丢 x 位)
    st = os.stat(target)
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except (PermissionError, AttributeError):
        pass
    os.replace(tmp, target)
    # 复核
    check = Elf(target)
    for (_k, off, size, _o, new, _n) in edits:
        assert bytes(check.data[off:off + size]) == new, "复核失败 @0x%x" % off
    print("已写入并复核 %d 处补丁。重启微信生效。" % n)

    if out_dir:
        launcher = os.path.join(out_dir, "wechat-patched")
        exe = None
        for dirpath, _d, files in os.walk(os.path.join(out_dir, "squashfs-root")):
            if "wechat" in files and os.path.getsize(
                    os.path.join(dirpath, "wechat")) > 50 * 1024 * 1024:
                exe = os.path.join(dirpath, "wechat")
                break
        if exe:
            with open(launcher, "w") as f:
                f.write("#!/bin/sh\nexec '%s' \"$@\"\n" % exe)
            os.chmod(launcher, 0o755)
            print("启动器: %s" % launcher)


def cmd_restore(args):
    target, _ = load_target(args)
    bak = backup_path(target)
    if not os.path.exists(bak):
        raise SystemExit("找不到备份: %s" % bak)
    shutil.copy2(bak, target)
    print("已还原: %s <- %s" % (target, bak))


def cmd_status(args):
    target, _ = load_target(args)
    elf = Elf(target)
    bid = elf.build_id()
    rep = analyze(elf, verbose=False)
    edits = plan_corrupt_key(elf, rep)
    # 补丁态检测: 搜索被改写后的乱串 (原串已不存在, 不能只靠 edits)
    needle = dict((t, n) for t, n, _d in ANCHORS)["revokemsg"]
    mm = mangle(needle)
    patched_sites = []
    for o in find_all(elf.data, mm):
        va = elf.off2va(o)
        if va is not None and lea_xref_map(elf, [va]).get(va):
            patched_sites.append(o)
    print("目标 : %s" % target)
    print("构建 : %s%s" % (bid, " (已验证版本)" if bid == VERIFIED_BUILDID else ""))
    print("备份 : %s" % (backup_path(target) if os.path.exists(
        backup_path(target)) else "无"))
    if patched_sites:
        print("状态 : 已打补丁 (%d 处: %s)" % (
            len(patched_sites), " ".join("0x%x" % x for x in patched_sites)))
    elif edits:
        print("状态 : 未打补丁 (可补丁位置 %d 处)" % len(edits))
    else:
        print("状态 : 锚点缺失/不适用 (版本可能已变化, 请 analyze)")


def main():
    ap = argparse.ArgumentParser(
        description="Linux 微信 4.x 防撤回一键补丁 (零依赖, 可逆)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("-f", "--file", help="直接指定 wechat ELF 路径")
        p.add_argument("--appimage", help="AppImage 路径(自动解包打补丁)")
        return p

    common(sub.add_parser("analyze", help="只分析不修改"))
    p = common(sub.add_parser("patch", help="备份并打补丁"))
    p.add_argument("--strategy", choices=["corrupt-key", "nop-calls", "ret0"],
                   default="corrupt-key")
    p.add_argument("--func", help="nop-calls/ret0 的目标函数 VA (如 0x60de123)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-y", "--yes", action="store_true", help="跳过版本确认")
    common(sub.add_parser("restore", help="还原备份"))
    common(sub.add_parser("status", help="查看状态"))
    args = ap.parse_args()
    {"analyze": cmd_analyze, "patch": cmd_patch,
     "restore": cmd_restore, "status": cmd_status}[args.cmd](args)


if __name__ == "__main__":
    main()
