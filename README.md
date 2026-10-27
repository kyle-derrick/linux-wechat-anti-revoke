# linux-wechat-anti-revoke

> Linux 微信 4.x 防撤回一键补丁 —— 纯 Python 标准库、零依赖、完全可逆

对方撤回消息后，**原消息保留不再消失**。原理与 [RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) 一脉相承（"让撤回分支永不执行"），针对微信 4.x Linux 原生客户端适配。

```bash
sudo python3 wx_linux_anti_revoke.py patch    # 就这一条, 即完成分析/校验/备份/写入/复核
```

---

## ⚠️ 免责声明

- 本项目**仅供个人学习、研究与技术交流**使用，不得用于任何商业用途。
- 使用本项目产生的任何后果由使用者自行承担，与作者无关。
- 本项目只修改用户本机已合法安装的软件文件，**不分发任何第三方软件的修改版本**。
- 修改客户端可能违反腾讯服务条款，理论存在账号风险，请自行评估。
- 如有侵权或违反相关方政策，请联系作者立即删除。

---

## 原理

微信 4.x 主程序（`/opt/wechat/wechat`，stripped PIE ELF）内有一张**消息字段名池**，
撤回同步消息的解析代码通过 `lea reg,[rip+X]` 直接引用池中的明文键 `"revokemsg"`
来识别撤回指令：

```
解析函数 (0x60de400 附近):
  lea rsi, [rip+…]   ; → 字段名池中的 "revokemsg"
  lea rdi, <键对象>
  call <比较/查表>    ; 键名匹配 → 进入撤回处理分支
```

本脚本把池中的 `"revokemsg"` **原地改写为等长乱串 `"revokemsq"`**：

- 撤回指令键永远匹配失败 → 撤回指令被当作未知消息忽略 → **原消息保留**；
- **不修改任何机器码**、不碰函数入口，只有 9 个字节的数据改动；
- 所有引用该键的代码路径一致失配（本构建实测 3 处引用），行为可预期；
- 自动备份原文件，`restore` 一条命令字节级还原。

自己主动撤回消息走另一条路径（`/cgi-bin/micromsg-bin/revokemsg` CGI，
独立字符串、未被触碰），**不受影响**。

## 特性

- ✅ 零依赖：纯 Python 标准库（3.8+），无需 root 之外任何环境
- ✅ 一键化：`patch` 自动完成分析、定位、校验、备份、写入、复核
- ✅ 可逆：自动备份为 `.wxrevoke.bak`，`restore` 字节级还原
- ✅ 防呆：内置已验证构建的 build-id 校验；写入前逐字节比对预期值，不符即中止
- ✅ 可适配：`analyze` 输出锚点与代码交叉引用，新版本可快速定位

## 适用环境

| 项目 | 要求 |
|---|---|
| 系统 | Linux x86_64（Deepin / UOS / Ubuntu / Arch / 麒麟等均可） |
| 微信 | 微信 Linux 原生版 4.x（deb / rpm / AppImage 安装均可） |
| Python | 3.8 或更高 |
| 权限 | patch/restore 需要 root（sudo） |

**已实测验证的构建**（脚本内置其 build-id，匹配时不会弹确认）：

| 日期 | 来源 | build-id |
|---|---|---|
| 2026-10-26 验证 | 官方 [WeChatLinux_x86_64.deb](https://dldir1v6.qq.com/weixin/Universal/Linux/WeChatLinux_x86_64.deb)（2026-10-12 构建） | `d62bde21b26c5928e7dea826271e21a542b755b5` |

其他 4.x 版本大概率同样适用（字段名池是稳定结构），脚本会自动分析并提示。

---

## 使用教程

### 第 0 步：准备

```bash
# 确认 Python 版本 ≥ 3.8
python3 --version

# 下载脚本（二选一）
git clone https://github.com/kyle-derrick/linux-wechat-anti-revoke.git
# 或只下载单个文件:
wget https://raw.githubusercontent.com/kyle-derrick/linux-wechat-anti-revoke/main/wx_linux_anti_revoke.py
```

### 第 1 步：安装微信（已装可跳过）

```bash
wget https://dldir1v6.qq.com/weixin/Universal/Linux/WeChatLinux_x86_64.deb
sudo apt install ./WeChatLinux_x86_64.deb     # 或: sudo dpkg -i ./WeChatLinux_x86_64.deb
# rpm 系: sudo rpm -ivh WeChatLinux_x86_64.rpm 或 sudo dnf install ./xxx.rpm
```

### 第 2 步：关闭微信

补丁会改写主程序文件，微信运行时文件被系统锁定（ETXTBSY），必须先退出：

```bash
pgrep -a wechat && pkill wechat || echo "微信未运行，可以继续"
```

### 第 3 步：分析（可选但推荐，不改任何字节）

```bash
cd linux-wechat-anti-revoke
sudo python3 wx_linux_anti_revoke.py analyze
```

正常输出应类似：

```
BUILD : d62bde21b26c5928e7dea826271e21a542b755b5  <- 本脚本实测验证过的构建
[锚点] revokemsg       x5   撤回指令键 (默认补丁目标)
---- 代码交叉引用 ----
revokemsg  str@0xf7d9cc  va=0xf7d9cc  xref=3: 0x60de40a 0x60ebbad 0x60ebbc3
```

**判读**：`revokemsg` 锚点存在且有 `xref≥1` → 可以打补丁；否则见 [FAQ](#faq)。

### 第 4 步：打补丁

```bash
# 先预览补丁计划（不写入）
sudo python3 wx_linux_anti_revoke.py patch --dry-run
# 预期输出:
#   corrupt-key @0xf7d9cc  7265766f6b656d7367 -> 7265766f6b656d7371  (xref=3 ...)

# 正式写入（自动备份 + 写后复核）
sudo python3 wx_linux_anti_revoke.py patch
# 预期输出: 已写入并复核 1 处补丁。重启微信生效。
```

> AppImage 用户请看 [AppImage 专节](#appimage-用户)。

### 第 5 步：启动微信并验证

| 测试项 | 预期结果 |
|---|---|
| 对方撤回消息 | ✅ **原消息保留**（核心成功标准） |
| 是否显示"撤回了一条消息"提示 | 当前模式通常**无提示**（撤回指令被整体忽略） |
| 自己在电脑上撤回 | ✅ 正常（主动撤回不受影响） |
| 在手机上撤回 | 电脑端消息保留不消失 |
| 程序稳定性 | 收发消息、崩溃情况正常 |

> 想要"消息保留 + 显示撤回提示"的效果，需要拦截撤回链中"删原消息"、放行"插提示"
> 两步（进阶策略，见 `analyze` 输出的 0x60de4xx 函数簇 + `nop-calls`），欢迎反馈实测结果。

### 日常维护

```bash
# 查看当前状态（微信升级后先跑这个）
sudo python3 wx_linux_anti_revoke.py status

# 还原（字节级，随时可用）
sudo python3 wx_linux_anti_revoke.py restore
```

**微信自动更新/重装会覆盖补丁**：更新后重跑一次 `patch` 即可。
若版本变化较大（build-id 不同），脚本会警告并要求确认，此时先 `analyze`
确认 `revokemsg` 锚点仍有 xref 再打。

### AppImage 用户

```bash
sudo python3 wx_linux_anti_revoke.py patch --appimage ./WeChatLinux_x86_64.AppImage
# 自动解包到 ./wx_patched/squashfs-root → 打补丁 → 生成启动器
./wx_patched/wechat-patched    # 用启动器运行打补丁后的微信
```

---

## FAQ

**Q: 补丁后微信启动报 Permission denied？**
旧版脚本的一个已知问题（写入时丢失可执行位），一条命令修复：
```bash
sudo chmod 755 /opt/wechat/wechat
```
（当前版本脚本已修复，会在替换前保留原权限与属主。）

**Q: analyze 提示锚点缺失 / xref=0？**
说明腾讯改版导致锚点结构变化。请把完整的 `analyze` 输出贴到
[Issues](../../issues)，新版本通常只需重新确认锚点偏移。

**Q: patch 提示"构建与已验证版本不同"？**
不一定是坏事——字段名池结构在 4.x 系列很稳定。先 `analyze` 看
`revokemsg` 是否有 xref，有就加 `-y` 继续；没有就等适配（欢迎提 issue）。

**Q: 撤回提示能保留吗？**
当前默认模式（corrupt-key）让撤回指令整体失效，**消息保留但无提示**。
"保留 + 提示"需要更精细的调用点拦截，路线图见上。

**Q: 会封号吗？**
修改客户端违反微信用户协议，理论存在风险。社区同类工具使用多年
未见因防撤回封号的公开案例，但请自行评估，建议先用小号验证。

**Q: 支持微信 3.9 或更老的 Linux 版？**
不支持。3.x 时代的 Linux 微信（Electron/UOS 版）架构完全不同，
那个时代请用 [RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher)（Windows）。

---

## 技术细节

<details>
<summary>锚点与策略（点开）</summary>

| 锚点串 | 出现次数 | 代码引用 | 说明 |
|---|---|---|---|
| `revokemsg` | 5 | **3**（默认补丁目标） | 撤回指令键 |
| `revoketime` | 1 | 2 | 撤回时间字段 |
| `replacemsg` | 1 | 2 | 撤回替换提示键 |
| `sysmsgtemplate` | 1 | 2 | 系统消息模板 |
| `newmsgid` / `svrid` | 3 / 19 | 4 / 9 | 消息定位字段 |

所有撤回相关键的引用聚集在 `0x60de400`–`0x60de850` 约 1KB 的同一解析函数内，
即撤回消息处理代码所在。

三种策略：
- `corrupt-key`（默认）：改写字段名池中被代码引用的 `revokemsg` 键，等长乱串，零代码改动；
- `nop-calls --func 0xVA`：NOP 掉所有对指定函数的直接调用（`E8 rel32` → 5×`90`）；
- `ret0 --func 0xVA`：函数入口写 `xor eax,eax; ret`。

进阶策略需要先用 Ghidra/objdump 确认函数入口 VA（`analyze` 的 xref 输出即入口线索）。
注意本构建无 `endbr64`、几乎无 rbp 帧指针（重度 -O2），函数入口需按调用目标回溯判断。

</details>

## 参考与致谢

思路与经验来自这些项目（本项目未复制其任何代码）：

- [huiyadanli/RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) — 经典防撤回补丁（Windows）
- [zetaloop/BetterWX](https://github.com/zetaloop/BetterWX) — 微信 4.x 撤回处理链研究
- [EEEEhex/RevokeHook](https://github.com/EEEEhex/RevokeHook) — 符号恢复 + 带提醒方案
- [lmclmc/linux-wechat-hook](https://github.com/lmclmc/linux-wechat-hook) — Linux ELF hook 先例
- [52pojie 吾爱破解](https://www.52pojie.cn/) 相关讨论帖

## License

MIT
