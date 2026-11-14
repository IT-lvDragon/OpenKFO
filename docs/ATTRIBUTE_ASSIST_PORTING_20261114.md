# AttributeAssist 开发与移植笔记（完整版）

日期：2026-11-14　对应版本：v1051（main @ 8b23939）
用途：把 `tools/AttributeAssist.py` 整体挪到其他项目时所需的全部上下文。目标项目代码与客户端一致（gfld.dat v1.13.0.590 同源）时**理论上零改动可用**，按下文第 6 节验证即可。
另见：[房间结算 4110 搁置问题](ROOM_SETTLE_4110_20261114.md)。

## 1. 架构原则

单文件 Python（tkinter GUI + ctypes），**外置跨进程**方案，无 DLL 注入：

- 内存读写：`ReadProcessMemory` / `WriteProcessMemory`（64 位 Python 操作 32 位游戏进程）。
- 代码执行：`VirtualAllocEx`（RWX）写入 shellcode blob → `CreateRemoteThread` 一次性执行 → 线程退出码 + 缓冲区快照回读结果。所有 shellcode 均带手动 SEH 帧（fs:[0]），异常时把寄存器快照写回缓冲区由工具翻译，保证客户端永不崩。
- 进程权限必须含 `PROCESS_CREATE_THREAD`（0x0002），否则远程线程恒 ACCESS_DENIED；`PROCESS_RIGHTS` 常量已含全套。
- 枚举 32 位进程需 `TH32CS_SNAPMODULE(0x8|0x10)`；进程名白名单 `PROCESS_NAMES = ("gfxz.dat", "gfld.dat")`，ImageBase 默认 0x400000。

## 2. 功能清单（对应 UI 分区）

| 分区 | 机制 |
|---|---|
| 功能（属性） | 每 100ms 按勾选写内存：怒气倍率/无敌/霸体/反伤值/防御值/吸血值（`FEATURES` 表，含 offset/是否走状态块/初值/换算） |
| 自动战斗 | 每 400ms 枚举敌方角色，经一次性远程线程调游戏原生发包/伤害函数（kill.h 移植：`kill_code`）；SEH 守卫 + 函数序言复查，秒杀/自杀延迟可调 |
| 自动跑图 | 后台按键模拟（不写内存），仅投递给游戏前台窗口 |
| 自动点击 / 操作序列 | 前台模拟鼠标/键盘组合，不写内存 |
| 结算重放 | E9 跳板钩住发包函数抓包（环形槽），改字节后经原生 send 原样重发；含结算模板、查找替换、发包间隔/次数（`replay_pushes`） |
| 自动结算 | `native_auto_tick`：进图（战斗管理器非空）后延迟 2.5s 调一次 `0x587E40`，客户端自行构造 4110；本局只发一次（重复 4110 有掉线风险） |
| 房间进局结算 | `native_enter_settle`：房间内（不进图）装假对象直接调 `0x587E40`，见第 5.3 节与搁置问题笔记 |
| 内存诊断 | EmptyWorkingSet 裁剪目标进程工作集（泄漏治标） |
| 其他 | 非管理员自动 UAC 重启；勾选/数值持久化 |

## 3. 版本适配机制

- 已知 gfxz.dat 哈希（`KNOWN_HASH`）直接放行；其他客户端仅警告不拦截。
- 危险操作（秒杀/原生结算）受**函数序言签名**保护，不符自动拒绝。当前签名表（RVA 均为 `VA - 0x400000`）：

| 常量 | RVA | 序言 SIG | 用途 |
|---|---|---|---|
| `KILL_SEND_OFF` | 0x63FBB0 | 0x51EC8B55 | 秒杀发包 |
| `KILL_DAMAGE_OFF` | 0x5F29F0 | 0x83EC8B55 | thiscall 伤害 |
| `KILL_HEALTH_OFF` | 0x5E45B0 | 0x81EC8B55 | 目标血量 |
| `NATIVE_SETTLE_FN` | 0x587E40 | `55 8B EC 81 EC 64 03 00 00` | 结算函数（拼 8×0x57 记录的 4110） |
| `NATIVE_ENTER_INIT` | 0x63EEA0 | `55 8B EC 6A FF 68 12 AA AD 00` | 进局初始化（已弃用，仅存档判定） |
| `NATIVE_SEND_CALL` | 0x588498 | `E8 B3 44 0B 00` | 0x587E40 内唯一 call 0x63C950 |
| `NATIVE_GUARD_SIGS` | 0x419120 / 0x4B3F0 | `55 8B EC 51` | 关卡获取/在战斗判定守卫 |

## 4. 偏移/常量总表

- 基础：`MANAGER_PTR=0x13C8708`（游戏全局）、`INFO_PTR=0x13C86FC`、`UID_OFFSET=0xC90`、`STATE_OFFSET=0x1A6C`、战斗管理器 `NATIVE_SETTLE_MGR=0x13C8710`、ctx 指针 0x13C86F8。
- 属性：见 `FEATURES`（offset 相对 actor 或状态块）。
- 原生结算：`NATIVE_GAME_MGR=0x13C8708`、`NATIVE_STAGE_GET=0x419120`、`NATIVE_IN_BATTLE=0x4B3F0`、发送函数 `NATIVE_SEND_FN=0x63C950`（cdecl(id, a2, buf, len)）。
- 4110 包结构：696 字节 = 8×0x57 战绩记录整包，无包头；房间/局内差异字段与修法见搁置笔记。
- 房间结算 shellcode 缓冲区布局（4KB RWX 页）：+0x000 主流程 / +0x100 SEH 处理器 / +0x1F4 原链 +0x1F8 安装时 ESP / +0x200 寄存器快照 / +0x238 桩命中标志 +0x23C 包体指针 +0x240 记录0快照(备用) / +0x2F0 原值暂存 +0x300 假对象 +0x400 假虚表 +0x500 `xor eax,eax;ret` / +0x510 调用点原 8 字节 / +0x560 4110 修正桩。
- 房间结算要点：[mgr+0xAC]（对局结果对象）房间内是垃圾指针 → 写假对象（虚表 +0x98 槽指向 `xor eax,eax;ret`）走零值路径；**+0xAC 必须 disp32 编码**（disp8 0xAC 符号扩展成 -0x54，v1046 踩过）。

## 5. 关键机制与已踩的坑

1. **E8→E9 栈语义**（v1048 崩溃根因）：call 补丁成 jmp 后不压返回地址，桩放行前必须 `push 调用点返回地址` 再跳目标函数，否则目标函数栈整体错位 4 字节（把 id 当返回地址、包体指针读到小整数）。
2. **0x63EEA0 进局初始化**：房间内调用必崩（内部经运行时调用表派发，表未就绪；异常落点在动态内存），已弃用——房间内管理器本就非空，直接调结算函数即可。
3. **运行时解密区**：0x9E3C70/0x9E3CD0/0x9E45B0/0x9E5570 等 actor getter 静态字节是壳加密乱码，无法静态分析；其产出只能在发送点拦截改写。
4. **capstone 自检注意**：op_str 不含助记符；rep 前缀并入助记符（`rep movsb`）；≥0x10 的偏移渲染为 hex（`[esp + 0x20]`）；RVA 当 VA 过滤会错。
5. **线性反汇编**：跨 0xFF 零填充会吞 0x100 边界，关键区域（SEH 处理器）需独立反汇编。
6. **自检**：`enter_settle_code_self_test` 字节级 + capstone 语义双验（buf=0 时全部绝对地址确定），构建前必跑；`/tmp/run_selftests.py`（stub ctypes 后 import 模块）+ `py_compile`。

## 6. 移植到新项目：步骤与验证

1. **拷贝文件**：`tools/AttributeAssist.py`、`tools/AttributeAssist.spec`。exe 产物名固定 `AttributeAssist.exe`（不版本化，发布流程依赖此名）。
2. **客户端同源时**：偏移/签名理论上全部适用，直接跑第 3 步。
3. **验证顺序**：
   - 进程附加：打开游戏 → 进程列表出现 → 启动（管理员一致性：游戏管理员则工具也要）；
   - 属性功能逐项勾选生效、取消恢复；
   - 秒杀：进图后启用（序言 SIG 不符会自动拒绝并提示——若提示说明客户端与预期不同源）；
   - 自动结算：进图后 2.5s 自动发 4110；
   - `python3 /tmp/run_selftests.py` 自检 PASS。
4. **若客户端版本/基址不同**（SIG 校验失败时重新定位）：
   - 用 IDA/x64dbg 按第 3 节函数特征（序言 + 调用关系）重新找 RVA：结算函数按「push 0x2b8 + lea [ebp-0x2c0] + push 0x100e + call 发送函数」的拼包特征搜；
   - ImageBase 不同改 `BASE_FALLBACK` 并确认 rva2off 换算（`0x600 + (rva - 0x1000)`，本客户端 .text 特例）；
   - 结构体偏移（actor +0xC90/+0x1A6C、FEATURES、mgr+0xAC）需逐一重验。
5. **构建**：`WINEPREFIX=/workspace/.wine-prefix wine /workspace/.wine-env/python/python.exe -m PyInstaller --noconfirm --clean AttributeAssist.spec`（cwd=tools）；产物校验脚本核对 CArchive 条目（pyi_rth__tkinter/_tcl_data）与内嵌标记（enter_sig/cn_btn/impl_name/const_name/ver）。
6. **git 交付**：dist 在 .gitignore 内，exe 需 `git add -f`；提交身份 `IT-lvDragon <IT-lvDragon@users.noreply.github.com>`；push `origin trae/agent-5TunpF:main`。

## 7. 已知未决问题

- **房间内一键结算无奖励**（搁置）：链路全通、字段修正确认生效，服务器仍拒发——判定服务器校验不只包内容。完整分析、hex 存档与 4 条候选思路见 [ROOM_SETTLE_4110_20261114.md](ROOM_SETTLE_4110_20261114.md)。
- 已明确不做：模板重放、高频轮询（用户决策）。

## 8. 相关文件

- `tools/AttributeAssist.py` — 全部源码（单文件，注释即文档）
- `tools/AttributeAssist.spec` — PyInstaller 打包配置
- `docs/ROOM_SETTLE_4110_20261114.md` — 4110 搁置问题专篇
- `/tmp/verify_final.py`、`/tmp/run_selftests.py` — 校验/自检脚本（会话临时件，未入库）
