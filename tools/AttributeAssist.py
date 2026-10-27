"""gfxz/gfld 单机属性助手（外置版：跨进程读写 + 一次性远程线程，无 DLL 注入）。

移植自 tools/game-mod/main.cpp 与 kill.h：
- 属性：怒气倍率/无敌/霸体/反伤/防御/吸血，每 100ms 执行勾选项，取消勾选恢复原值。
- 秒杀：每 400ms 一轮，枚举敌方角色后逐个经一次性远程线程调用原生发包/伤害函数。
- 版本校验：已知 gfxz.dat 哈希直接放行；其他客户端（gfld.dat 或更新版）仅警告不拦截，
  秒杀仍受函数序言检查保护（序言不符自动拒绝），属性写入无保护，风险自负。
"""
import ctypes
import json
import os
import struct
import sys
import time
from ctypes import wintypes

# ---- 偏移常量（main.cpp / kill.h，gfxz.dat 1B7C8676 实测）----
MANAGER_PTR = 0x13C8708               # 全局管理器指针
INFO_PTR = 0x13C86FC                  # 本地玩家信息指针
UID_OFFSET = 0xC90                    # actor+0xC90 = uid (8 字节)
STATE_OFFSET = 0x1A6C                 # actor+0x1A6C = 战斗状态块

# 与 main.cpp 的 OpenProcess 一致：缺 PROCESS_CREATE_THREAD(0x0002) 时
# CreateRemoteThread 恒返回 ACCESS_DENIED，秒杀的远程线程永远创建失败。
PROCESS_RIGHTS = 0x0400 | 0x0008 | 0x0010 | 0x0020 | 0x0002 | 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8 | 0x10        # 64 位 Python 枚举 32 位游戏进程需含 MODULE32
MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
MEM_RELEASE = 0x8000
BASE_FALLBACK = 0x400000              # 32 位 exe 默认 ImageBase

KNOWN_HASH = "1B7C8676E778C7BD47F55184F927338DA3CF70C6AA5F0BEB59869EA0F0AC9D4E"
CLIENT_HASHES = {KNOWN_HASH, KNOWN_HASH.lower()}
PROCESS_NAMES = ("gfxz.dat", "gfld.dat")

FEATURES = [
    dict(name="怒气倍率", offset=0x80, use_state=True, is_int=False, initial="999", scale=1),
    dict(name="无敌", offset=0x1780, use_state=False, is_int=True, initial="1", scale=1),
    dict(name="霸体", offset=0x64, use_state=True, is_int=True, initial="1", scale=1),
    dict(name="反伤值", offset=0x1BD0, use_state=False, is_int=False, initial="1", scale=1),
    dict(name="防御值", offset=0x78, use_state=True, is_int=False, initial="1", scale=1),
    dict(name="吸血值（原版输入单位）", offset=0x6C, use_state=True, is_int=False, initial="10", scale=0.1),
]

# ---- 秒杀：移植自 tools/game-mod/kill.h ----
KILL_SEND_OFF = 0x63FBB0              # 发包函数，序言 0x51EC8B55
KILL_DAMAGE_OFF = 0x5F29F0            # thiscall 伤害调用，序言 0x83EC8B55
KILL_HEALTH_OFF = 0x5E45B0            # 目标血量读取，序言 0x81EC8B55

# ---- Win32 绑定 ----
k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
_handle = wintypes.HANDLE
k32.GetCurrentProcess.restype = _handle
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAlloc.restype = _handle
k32.VirtualFree.argtypes = [_handle, ctypes.c_void_p, wintypes.DWORD]
k32.VirtualFree.restype = wintypes.BOOL


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_uint64),   # ULONG_PTR
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),        # 4 字节，568 字节结构的关键
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260),
                ("dwFlags", wintypes.DWORD)]


k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = _handle
k32.CloseHandle.argtypes = [_handle]
k32.CloseHandle.restype = wintypes.BOOL
k32.GetProcessId.argtypes = [_handle]
k32.GetProcessId.restype = wintypes.DWORD
k32.WaitForSingleObject.argtypes = [_handle, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.ReadProcessMemory.argtypes = [_handle, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.WriteProcessMemory.argtypes = [_handle, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL
k32.VirtualAllocEx.argtypes = [_handle, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualFreeEx.argtypes = [_handle, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
k32.VirtualFreeEx.restype = wintypes.BOOL
k32.VirtualProtectEx.argtypes = [_handle, ctypes.c_void_p, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.VirtualProtectEx.restype = wintypes.BOOL
k32.FlushInstructionCache.argtypes = [_handle, ctypes.c_void_p, ctypes.c_size_t]
k32.FlushInstructionCache.restype = wintypes.BOOL
k32.CreateRemoteThread.argtypes = [_handle, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
k32.CreateRemoteThread.restype = _handle
k32.QueryFullProcessImageNameW.argtypes = [_handle, wintypes.DWORD, ctypes.c_wchar_p,
                                           ctypes.POINTER(wintypes.DWORD)]
k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = _handle
k32.Process32FirstW.argtypes = [_handle, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32FirstW.restype = wintypes.BOOL
k32.Process32NextW.argtypes = [_handle, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.restype = wintypes.BOOL
k32.Module32FirstW.argtypes = [_handle, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32FirstW.restype = wintypes.BOOL


# ---- 内存读写 ----
def read_mem(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)) \
            or got.value != size:
        return None
    return buf.raw


def write_mem(handle, addr, data):
    data = bytes(data)
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(addr), data, len(data),
                                       ctypes.byref(got))) and got.value == len(data)


def read_u32(handle, addr):
    raw = read_mem(handle, addr, 4)
    return struct.unpack("<I", raw)[0] if raw else None


def read_u64(handle, addr):
    raw = read_mem(handle, addr, 8)
    return struct.unpack("<Q", raw)[0] if raw else None


def write_u32(handle, addr, value):
    return write_mem(handle, addr, struct.pack("<I", value & 0xFFFFFFFF))


# ---- 进程与模块 ----
LAST_SNAP_ERROR = ""


def find_processes():
    """枚举 gfxz.dat / gfld.dat 进程，返回 [(pid, name)]。"""
    global LAST_SNAP_ERROR
    LAST_SNAP_ERROR = ""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) or 0
    if not snap:
        LAST_SNAP_ERROR = f"进程快照失败（错误码 {ctypes.get_last_error()}）"
        return []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    found = []
    ok = k32.Process32FirstW(snap, ctypes.byref(entry))
    seen = set()
    while ok:
        pid = entry.th32ProcessID
        if pid in seen:
            break
        seen.add(pid)
        name = entry.szExeFile or ""
        if name.lower() in PROCESS_NAMES:
            found.append((pid, name))
        ok = k32.Process32NextW(snap, ctypes.byref(entry))
    if not found and not seen:
        err = k32.GetLastError()
        LAST_SNAP_ERROR = (f"进程枚举失败（错误码 {err}，结构体 {ctypes.sizeof(entry)} 字节）；"
                           "每秒自动重试。")
    k32.CloseHandle(snap)
    return found


def query_image_path(handle):
    buf = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(32768)
    if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        return buf.value
    return ""


def file_sha256(path):
    import hashlib
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fp:
            for chunk in iter(lambda: fp.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest().upper()


def module_base(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) or 0
    if not snap:
        return 0
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
    base = 0
    if k32.Module32FirstW(snap, ctypes.byref(entry)):
        base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
    k32.CloseHandle(snap)
    return base


# ---- 角色解析 ----
def now_ms():
    return int(time.monotonic() * 1000)


def resolve_actor(handle, manager, uid):
    """按 UID 在管理器红黑树中找 actor，返回 (ptr, state, uid) 或 None。与 main.cpp resolve 一致。"""
    if not uid or not manager:
        return None
    head = read_u32(handle, manager + 0x2F0)
    if not head:
        return None
    root = read_u32(handle, head + 4)
    if not root:
        return None
    seen = set()
    pending = [root]
    while pending and len(seen) < 128:
        node = pending.pop()
        if not node or node == head or node in seen:
            continue
        seen.add(node)
        raw = read_mem(handle, node, 24)
        if not raw:
            return None
        left, _parent, right, key, value = struct.unpack_from("<5I", raw)
        if raw[21]:  # nil 哨兵节点
            continue
        pending.append(left)
        pending.append(right)
        if value:
            found = read_u64(handle, value + UID_OFFSET)
            if found == uid:
                state = read_u32(handle, value + STATE_OFFSET)
                if state:
                    return (value, state, uid)
    return None


def list_actors(handle, manager):
    """管理器红黑树全量遍历，返回 (ok, [(ptr, state, uid)])。与 kill.h listActors 一致。"""
    out = []
    if not manager:
        return False, out
    head = read_u32(handle, manager + 0x2F0)
    if not head:
        return False, out
    root = read_u32(handle, head + 4)
    if not root:
        return False, out
    seen = set()
    pending = [root]
    while pending and len(seen) < 128:
        node = pending.pop()
        if not node or node == head or node in seen:
            continue
        seen.add(node)
        raw = read_mem(handle, node, 24)
        if not raw:
            return False, out
        left, _parent, right, key, value = struct.unpack_from("<5I", raw)
        if raw[21]:  # nil 哨兵节点
            continue
        pending.append(left)
        pending.append(right)
        if key < 40 and value:
            uid = read_u64(handle, value + UID_OFFSET)
            state = read_u32(handle, value + STATE_OFFSET) if uid else 0
            if uid and state:
                out.append((value, state, uid))
    return not pending, out


# ---- 特征读写 ----
class Feature:
    def __init__(self, spec):
        self.name = spec["name"]
        self.offset = spec["offset"]
        self.use_state = spec["use_state"]
        self.is_int = spec["is_int"]
        self.initial = spec["initial"]
        self.scale = spec["scale"]
        self.saved = False
        self.original = 0
        self.last = 0


def feature_address(actor, f):
    return (actor[1] if f.use_state else actor[0]) + f.offset


def feature_current(handle, actor, f):
    return read_u32(handle, feature_address(actor, f))


def feature_desired(text, f):
    """输入解析：整型开关恒写 1；浮点 0–999 × scale。返回 (bits, ok)。"""
    if f.is_int:
        return 1, True
    try:
        v = float(str(text).strip())
    except ValueError:
        return 0, False
    if v != v or v in (float("inf"), float("-inf")) or not 0 <= v <= 999:
        return 0, False
    return struct.unpack("<I", struct.pack("<f", v * f.scale))[0], True


def format_value(v, is_int):
    if is_int:
        return str(v)
    return f"{struct.unpack('<f', struct.pack('<I', v))[0]:.4g}"


def feature_restore(handle, actor, f):
    """恢复原值；游戏自己改过字段（当前值 != last）则保留新值。"""
    if not f.saved:
        return True
    ok = True
    if actor and actor[1]:
        v = feature_current(handle, actor, f)
        if v is None:
            ok = False
        elif v == f.last and not write_u32(handle, feature_address(actor, f), f.original):
            ok = False
    if ok:
        f.saved = False
    return ok


# ---- 秒杀 ----
def round_summary(done, skipped, reasons, cancelled):
    """每轮结束的状态行：完成/跳过计数 + 拒绝原因分布（诊断用）。"""
    detail = "，".join(f"{tag}×{count}" for tag, count in
                       sorted(reasons.items(), key=lambda item: (-item[1], item[0])))
    text = f"{'已停止' if cancelled else '本次结束'}：完成 {done}，跳过 {skipped}"
    if detail:
        text += f"（{detail}）"
    return text + "。"


def round_due(now, previous, busy, paused, wanted):
    return (not busy) and (not paused) and wanted and now - previous >= 400


def parse_delay_ms(text, default=10000):
    """自杀/秒杀延迟输入解析：秒 → 毫秒。
    空输入与 0 视为立即执行；非法回退默认；负数归零；上限 1 小时。"""
    text = str(text).strip()
    if not text:
        return 0
    try:
        value = int(float(text))
    except ValueError:
        return default
    return max(0, min(value * 1000, 3600 * 1000))


def make_kill(handle, base, own, enemy, reasons=None, suicide=False):
    """移植 makeKill：全部前置检查通过后生成调用参数；失败返回 None。
    own/enemy 为 (ptr, state, uid)；reasons 收集拒绝原因，供状态行诊断显示。
    suicide=True 时目标即自己（target=source=own uid），跳过目标与队伍检查。"""
    def refuse(tag):
        if reasons is not None:
            reasons[tag] = reasons.get(tag, 0) + 1
        return None

    if not suicide and (enemy[2] == own[2] or not enemy[1]):
        return refuse("目标无效")
    if read_u32(handle, own[0] + 0x7C) != 1:
        return refuse("自身未激活")
    if read_u32(handle, enemy[0] + 0x7C) != 1:
        return refuse("目标未激活")
    if not read_u32(handle, own[0] + 0xCE0):
        return refuse("自身无动作")
    if not read_u32(handle, enemy[0] + 0xCE0):
        return refuse("目标无动作")
    own_team = read_u32(handle, own[0] + 0x28)
    enemy_team = read_u32(handle, enemy[0] + 0x28)
    if own_team is None or enemy_team is None:
        return refuse("内存读取失败")
    if own_team == enemy_team and not suicide:
        return refuse("同队")
    manager = read_u32(handle, base + MANAGER_PTR)
    if not manager:
        return refuse("无管理器")
    context = read_u64(handle, manager + 0x311)
    if not context:
        return refuse("无轮次上下文")

    k = {"source": own[0], "target": enemy[0], "state": enemy[1],
         "send": base + KILL_SEND_OFF, "damage": base + KILL_DAMAGE_OFF,
         "health": base + KILL_HEALTH_OFF,
         "bits": struct.unpack("<I", struct.pack("<f", 9999.0))[0],
         "packet": bytearray(94), "effect": [0] * 8, "guards": []}
    pkt = k["packet"]
    pkt[4:12] = struct.pack("<Q", own[2])
    pkt[39:47] = struct.pack("<Q", enemy[2])
    pkt[47:55] = struct.pack("<Q", own[2])
    pkt[65] = 1
    pkt[67:71] = struct.pack("<I", k["bits"])
    pkt[86:94] = struct.pack("<Q", context)
    target_action = read_u32(handle, enemy[0] + 0xCE4)
    if target_action is None:
        return refuse("内存读取失败")
    pkt[55] = target_action & 0xFF
    guards = k["guards"]
    guards += [(base + MANAGER_PTR, manager),
               (manager + 0x311, context & 0xFFFFFFFF),
               (manager + 0x315, (context >> 32) & 0xFFFFFFFF)]
    for a in (own, enemy):
        guards += [(a[0] + 0xC90, a[2] & 0xFFFFFFFF),
                   (a[0] + 0xC94, (a[2] >> 32) & 0xFFFFFFFF),
                   (a[0] + 0x1A6C, a[1]), (a[0] + 0x7C, 1)]
    guards += [(own[0] + 0x28, own_team), (enemy[0] + 0x28, enemy_team)]

    # 函数序言是唯一的运行时版本门禁：未知客户端偏移不符时自动拒绝。
    for addr, expect in ((k["send"], 0x51EC8B55), (k["health"], 0x81EC8B55),
                         (k["damage"], 0x83EC8B55)):
        if read_u32(handle, addr) != expect:
            return refuse("函数序言不符")
    return k


class Code32:
    def __init__(self):
        self.b = bytearray()

    def bytes_(self, seq):
        self.b += bytes(seq)

    def word(self, v):
        self.b += struct.pack("<I", v & 0xFFFFFFFF)

    def hole(self):
        p = len(self.b)
        self.word(0)
        return p

    def patch(self, p, v):
        struct.pack_into("<I", self.b, p, v & 0xFFFFFFFF)

    def rel(self, p, target):
        self.patch(p, (target - p - 4) & 0xFFFFFFFF)

    def push(self, v):
        self.bytes_((0x68,))
        self.word(v)

    def call(self, address):
        self.bytes_((0xB8,))
        self.word(address)
        self.bytes_((0xFF, 0xD0))

    def status(self, address, v):
        self.bytes_((0xC7, 0x05))
        self.word(address)
        self.word(v)


def kill_code(code_base, data_base, k):
    """逐字节移植 kill.h killCode：SEH 守卫 + 轮次复查 + 状态码写回。"""
    c = Code32()
    stale = []
    c.bytes_((0x55, 0x8B, 0xEC, 0x60, 0x83, 0xEC, 0x08))  # frame, pushad, SEH 节点
    c.bytes_((0xC7, 0x44, 0x24, 0x04))
    handler = c.hole()
    c.bytes_((0x64, 0xA1, 0, 0, 0, 0, 0x89, 0x04, 0x24, 0x64, 0x89, 0x25, 0, 0, 0, 0))
    for g in k["guards"]:
        c.bytes_((0x81, 0x3D))
        c.word(g[0])
        c.word(g[1])
        c.bytes_((0x0F, 0x85))
        stale.append(c.hole())
    if k["health"]:
        c.bytes_((0xB9,))
        c.word(k["target"])
        c.call(k["health"])
        c.bytes_((0xD9, 0x1D))
        c.word(data_base + 140)
        c.bytes_((0xA1,))
        c.word(data_base + 140)
        c.bytes_((0x85, 0xC0, 0x0F, 0x8E))
        stale.append(c.hole())
        c.bytes_((0x3D,))
        c.word(0x7F800000)
        c.bytes_((0x0F, 0x83))
        stale.append(c.hole())
    c.push(0)
    c.push(0)
    c.push(94)
    c.push(data_base)
    c.push(8121)
    c.call(k["send"])
    c.bytes_((0x83, 0xC4, 0x14))
    # 发包后复查：并发换局时不得触碰旧角色
    for g in k["guards"]:
        c.bytes_((0x81, 0x3D))
        c.word(g[0])
        c.word(g[1])
        c.bytes_((0x0F, 0x85))
        stale.append(c.hole())
    c.push(0)
    c.push(1)
    c.push(0)
    c.push(k["target"])
    c.push(k["source"])
    c.push(k["bits"])
    c.bytes_((0xB9,))
    c.word(k["target"])
    c.call(k["damage"])  # thiscall，被调方回收 24 字节
    c.bytes_((0x83, 0xF8, 0xFF, 0x0F, 0x84))
    rejected = c.hole()
    c.status(data_base + 128, 1)
    c.bytes_((0xE9,))
    success = c.hole()
    skip = len(c.b)
    c.status(data_base + 128, 2)
    c.bytes_((0xE9,))
    skipped = c.hole()
    reject = len(c.b)
    c.status(data_base + 128, 4)
    c.bytes_((0xE9,))
    reject_jump = c.hole()
    fault = len(c.b)
    c.status(data_base + 128, 3)
    cleanup = len(c.b)
    c.bytes_((0x8B, 0x04, 0x24, 0x64, 0xA3, 0, 0, 0, 0, 0x83, 0xC4, 0x08, 0x61, 0x33,
              0xC0, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00))
    c.patch(handler, code_base + len(c.b))
    # SEH 处理器：恢复到 fault 处带 SEH 节点的栈位置继续执行
    c.bytes_((0x8B, 0x44, 0x24, 0x0C, 0x8B, 0x54, 0x24, 0x08, 0x89, 0x90))
    c.word(0xC4)
    c.bytes_((0xC7, 0x80))
    c.word(0xB8)
    c.word(code_base + fault)
    c.bytes_((0x33, 0xC0, 0xC3))
    for p in stale:
        c.rel(p, skip)
    c.rel(rejected, reject)
    c.rel(success, cleanup)
    c.rel(skipped, cleanup)
    c.rel(reject_jump, cleanup)
    return bytes(c.b)


class KillJob:
    """移植 KillJob：一次性远程线程调用，结束后回收内存，不使用 TerminateThread。"""

    def __init__(self):
        self.thread = 0
        self.block = 0
        self.started = 0.0
        self.start_error = 0

    def busy(self):
        return bool(self.thread)

    def start(self, handle, k):
        if self.thread:
            return False
        self.start_error = 0
        block = k32.VirtualAllocEx(handle, None, 8192, MEM_COMMIT_RESERVE, PAGE_READWRITE) or 0
        if not block:
            self.start_error = ctypes.get_last_error()
            return False
        code = kill_code(block, block + 4096, k)
        got = ctypes.c_size_t(0)
        ok = len(code) <= 4096
        if ok:
            ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(block), bytes(code),
                                             len(code), ctypes.byref(got))) and got.value == len(code)
        if ok:
            ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(block + 4096),
                                             bytes(k["packet"]), 94,
                                             ctypes.byref(got))) and got.value == 94
        if ok:
            effect = (ctypes.c_uint32 * 8)(*k["effect"])
            ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(block + 4096 + 160),
                                             effect, 32, ctypes.byref(got))) and got.value == 32
        if ok:
            previous = wintypes.DWORD(0)
            ok = bool(k32.VirtualProtectEx(handle, ctypes.c_void_p(block), 4096,
                                           PAGE_EXECUTE_READ, ctypes.byref(previous)))
            k32.FlushInstructionCache(handle, ctypes.c_void_p(block), len(code))
        thread = 0
        if ok:
            thread = k32.CreateRemoteThread(handle, None, 0, ctypes.c_void_p(block),
                                            None, 0, None) or 0
            if not thread:
                self.start_error = ctypes.get_last_error()
        if not thread:
            k32.VirtualFreeEx(handle, ctypes.c_void_p(block), 0, MEM_RELEASE)
            self.block = 0
            return False
        self.thread, self.block, self.started = thread, block, time.monotonic()
        return True

    def poll(self, handle):
        if not self.thread:
            return -2
        if k32.WaitForSingleObject(self.thread, 0) != WAIT_OBJECT_0:
            return -1
        result = read_u32(handle, self.block + 4096 + 128) or 0
        k32.CloseHandle(self.thread)
        self.thread = 0
        k32.VirtualFreeEx(handle, ctypes.c_void_p(self.block), 0, MEM_RELEASE)
        self.block = 0
        return result


# ---- 自检：本进程合成内存，不注入任何代码 ----
def self_test():
    handle = k32.GetCurrentProcess() or 0
    # 合成树节点存 32 位指针：必须在低 4GB 分配（wine/64 位 Python 默认高地址会截断）
    buffer = k32.VirtualAlloc(0x00800000, 0x1400000, MEM_COMMIT_RESERVE, PAGE_READWRITE) or 0
    if buffer >= 0x100000000:
        k32.VirtualFree(buffer, 0, MEM_RELEASE)
        buffer = 0
    if not buffer:
        print("self-test: FAILED (no memory)")
        return 2
    base = buffer
    manager, head, node = base + 0x1000, base + 0x2000, base + 0x2100
    actor, state, info = base + 0x3000, base + 0x6000, base + 0x7000
    uid = 123456789

    def put(a, v):
        if not write_u32(handle, a, v):
            print("put FAILED at %s err %s base %s" %
                  (hex(a), ctypes.get_last_error(), hex(base)))
            raise SystemExit(3)

    ok = True
    put(manager + 0x2F0, head)
    put(head + 4, node)
    put(node, head)
    put(node + 8, head)
    put(node + 12, 0)
    put(node + 16, actor)
    write_mem(handle, actor + UID_OFFSET, struct.pack("<Q", uid))
    put(actor + STATE_OFFSET, state)
    a = resolve_actor(handle, manager, uid)
    ok = ok and a == (actor, state, uid)
    ok = ok and resolve_actor(handle, manager, uid + 1) is None
    ok = ok and resolve_actor(handle, 0, uid) is None
    put(node, node)  # 环形树必须终止
    ok = ok and resolve_actor(handle, manager, uid + 1) is None
    put(node, head)

    # 特征恢复语义（main.cpp restore）
    rage = Feature(FEATURES[0])
    put(state + 0x80, 17)
    ok = ok and write_u32(handle, state + 0x80, 22) and read_u32(handle, state + 0x80) == 22
    put(base + MANAGER_PTR, manager)
    put(base + INFO_PTR, info)
    write_mem(handle, info + 0x18, struct.pack("<Q", uid))
    my_actor = (actor, state, uid)
    rage.saved, rage.original, rage.last = True, 17, 22
    ok = ok and feature_restore(handle, my_actor, rage) \
        and read_u32(handle, state + 0x80) == 17 and not rage.saved
    rage.saved = True
    put(state + 0x80, 33)  # 游戏自己改了值 → 保留新值
    ok = ok and feature_restore(handle, my_actor, rage) and read_u32(handle, state + 0x80) == 33
    rage.saved = True
    put(state + 0x80, 22)
    ok = ok and feature_restore(handle, (actor, 0, uid), rage) and not rage.saved  # 角色失效

    # 输入解析
    bits, okv = feature_desired("999", rage)
    ok = ok and okv and bits == 0x4479C000  # 999.0f
    ok = ok and not feature_desired("1000", rage)[1]
    ok = ok and not feature_desired("-1", rage)[1]
    ok = ok and not feature_desired("abc", rage)[1]
    inv = Feature(FEATURES[1])
    ok = ok and feature_desired("任意", inv) == (1, True)
    lifesteal = Feature(FEATURES[5])
    ok = ok and feature_desired("10", lifesteal) == (0x3F800000, True)  # 10 × 0.1 = 1.0f

    # ---- 秒杀（kill.h 移植）：本进程合成内存，不注入任何代码 ----
    enemy, enemy_state = base + 0x9000, base + 0x9100
    node2 = base + 0x2200
    enemy_uid = uid + 1
    put(node + 8, node2)     # 树：own → enemy
    put(node2, head)         # node2.left
    put(node2 + 8, head)     # node2.right
    put(node2 + 12, 1)       # key=1 <40
    put(node2 + 16, enemy)
    write_mem(handle, enemy + UID_OFFSET, struct.pack("<Q", enemy_uid))
    put(enemy + STATE_OFFSET, enemy_state)
    put(enemy + 0x28, 2)     # 敌方队伍
    put(actor + 0x28, 1)     # 我方队伍
    put(enemy + 0x7C, 1)
    put(actor + 0x7C, 1)
    put(enemy + 0xCE0, 1)
    put(actor + 0xCE0, 1)
    put(enemy + 0xCE4, 7)    # targetAction
    put(base + MANAGER_PTR, manager)
    write_mem(handle, manager + 0x311, struct.pack("<Q", 0x1234567800000007))
    ok = ok and list_actors(handle, manager) == (True, [(actor, state, uid),
                                                        (enemy, enemy_state, enemy_uid)])

    # 函数序言未写入 → 全部拒绝（拒绝原因可诊断）
    reasons = {}
    ok = ok and make_kill(handle, base, (actor, state, uid),
                          (enemy, enemy_state, enemy_uid), reasons) is None
    ok = ok and reasons.get("函数序言不符") == 1
    prologues = {0x63FBB0: 0x51EC8B55, 0x5E45B0: 0x81EC8B55, 0x5F29F0: 0x83EC8B55}
    for off, value in prologues.items():
        put(base + off, value)

    own_a, enemy_a = (actor, state, uid), (enemy, enemy_state, enemy_uid)
    # 同队拒绝秒杀，且原因计数可见
    put(enemy + 0x28, 1)
    reasons = {}
    ok = ok and make_kill(handle, base, own_a, enemy_a, reasons) is None
    ok = ok and reasons.get("同队") == 1
    put(enemy + 0x28, 2)
    k = make_kill(handle, base, own_a, enemy_a)
    ok = ok and bool(k)
    if k:
        ok = ok and k["bits"] == 0x461C3C00 and k["packet"][65] == 1 and k["packet"][55] == 7
        ok = ok and struct.unpack_from("<Q", k["packet"], 39)[0] == enemy_uid
        ok = ok and struct.unpack_from("<Q", k["packet"], 86)[0] == 0x1234567800000007
        ok = ok and len(k["guards"]) == 13

    # 自杀：target=source=自己，绕过目标/队伍检查，其余检查与守卫不变
    reasons = {}
    ok = ok and make_kill(handle, base, own_a, own_a, reasons) is None
    ok = ok and reasons.get("目标无效") == 1
    s = make_kill(handle, base, own_a, own_a, reasons, suicide=True)
    ok = ok and bool(s)
    if s:
        ok = ok and struct.unpack_from("<Q", s["packet"], 39)[0] == uid
        ok = ok and struct.unpack_from("<Q", s["packet"], 47)[0] == uid
        ok = ok and s["bits"] == 0x461C3C00 and len(s["guards"]) == 13

    # 轮次状态行：拒绝原因分布
    ok = ok and round_summary(2, 3, {"同队": 2, "目标未激活": 1}, False) \
        == "本次结束：完成 2，跳过 3（同队×2，目标未激活×1）。"
    ok = ok and round_summary(0, 0, {}, True) == "已停止：完成 0，跳过 0。"

    # shellcode 结构完整性（语义已由 C++ killSelfTest 在真机上验证）
    code = kill_code(0x10000000, 0x20000000, s or k or {"guards": [], "health": 0,
                                                        "target": 0, "send": 0, "source": 0,
                                                        "bits": 0, "damage": 0})
    tail = code.rfind(b"\xC2\x04\x00")
    ok = ok and len(code) <= 4096 and code[0] == 0x55 and code[1] == 0x8B and code[2] == 0xEC
    ok = ok and tail != -1 and struct.unpack_from("<I", code, 11)[0] == 0x10000000 + tail + 3
    ok = ok and code.count(struct.pack("<I", 0x20000000 + 128)) == 4  # 状态码 1/2/4/3 写回

    ok = ok and not round_due(1399, 1000, False, False, True)
    ok = ok and round_due(1400, 1000, False, False, True)
    ok = ok and not round_due(1800, 1000, True, False, True)
    ok = ok and not round_due(1800, 1000, False, True, True)
    ok = ok and not round_due(1800, 1000, False, False, False)

    # 自杀延迟解析：秒→毫秒、空/0=立即执行、非法回退、负数归零、上限 1 小时
    ok = ok and parse_delay_ms("5") == 5000 and parse_delay_ms("0") == 0
    ok = ok and parse_delay_ms("") == 0 and parse_delay_ms("  ") == 0
    ok = ok and parse_delay_ms("abc") == 10000
    ok = ok and parse_delay_ms("-3") == 0 and parse_delay_ms("9999") == 3600000

    k32.VirtualFree(buffer, 0, MEM_RELEASE)
    print("self-test:", "ok" if ok else "FAILED")
    return 0 if ok else 2


# ---- 界面 ----
def settings_path():
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        return None
    folder = os.path.join(root, "OpenKFO")
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, "AttributeAssist.json")


def run_ui():
    import tkinter as tk
    from tkinter import ttk

    class App:
        def __init__(self, root):
            self.root = root
            root.title("属性助手 · 单机版")
            root.resizable(False, False)
            self.handle = 0
            self.base = 0
            self.actor = None
            self.pids = []
            self.features = [Feature(spec) for spec in FEATURES]
            # 秒杀调度状态（对应 kill.h 全局）
            self.kill_job = KillJob()
            self.kill_queue = []
            self.kill_next = 0
            self.kill_done = 0
            self.kill_skipped = 0
            self.kill_cancel = False
            self.auto_fault = False
            self.disconnect_pending = False
            self.last_round = 0
            self.current_target = None
            self.round_reasons = {}  # 本轮拒绝原因计数（诊断）

            top = ttk.Frame(root)
            top.pack(fill="x", padx=12, pady=(12, 4))
            self.combo = ttk.Combobox(top, state="readonly", width=36)
            self.combo.grid(row=0, column=0, padx=(0, 8))
            ttk.Button(top, text="启动", command=self.connect).grid(row=0, column=1, padx=(0, 4))
            ttk.Button(top, text="停止并断开", command=self.stop_clicked).grid(row=0, column=2)

            body = ttk.LabelFrame(root, text="功能（自动记住勾选与数值）")
            body.pack(fill="x", padx=12, pady=4)
            self.rows = []
            for i, f in enumerate(self.features):
                enabled = tk.BooleanVar(value=False)
                ttk.Checkbutton(body, text=f.name, variable=enabled,
                                command=self.save_settings).grid(row=i, column=0, sticky="w",
                                                                 padx=8, pady=4)
                entry = ttk.Entry(body, width=10)
                entry.insert(0, f.initial)
                if f.is_int:
                    entry.configure(state="disabled")
                entry.grid(row=i, column=1, padx=8)
                ttk.Label(body, text="当前值").grid(row=i, column=2)
                value = tk.StringVar(value="—")
                ttk.Label(body, textvariable=value, width=12).grid(row=i, column=3, sticky="w")
                self.rows.append((enabled, entry, value))

            killbox = ttk.LabelFrame(root, text="自动战斗（游戏原生调用：SEH 守卫 + 轮次复查）")
            killbox.pack(fill="x", padx=12, pady=(0, 4))
            self.kill_var = tk.BooleanVar(value=False)
            self.kill_armed_at = 0
            self.kill_delay = tk.StringVar(value="0")
            self.suicide_var = tk.BooleanVar(value=False)
            self.suicide_armed_at = 0
            self.suicide_delay = tk.StringVar(value="10")
            ttk.Checkbutton(killbox, text="自动秒杀敌方（9999 伤害，每 400ms 一轮）",
                            variable=self.kill_var,
                            command=self.save_settings).grid(row=0, column=0, sticky="w",
                                                             padx=8, pady=4)
            ttk.Label(killbox, text="秒杀延迟(秒)：").grid(row=0, column=1, sticky="e",
                                                          pady=4)
            ttk.Spinbox(killbox, from_=0, to=3600, width=6,
                        textvariable=self.kill_delay,
                        command=self.save_settings).grid(row=0, column=2, sticky="w",
                                                         pady=4)
            ttk.Checkbutton(killbox, text="自杀（对自己的角色打 9999 伤害，死后自动停）",
                            variable=self.suicide_var,
                            command=self.on_suicide_toggle).grid(row=1, column=0, sticky="w",
                                                                 padx=8, pady=4)
            ttk.Label(killbox, text="自杀延迟(秒)：").grid(row=1, column=1, sticky="e",
                                                          pady=4)
            ttk.Spinbox(killbox, from_=0, to=3600, width=6,
                        textvariable=self.suicide_delay,
                        command=self.save_settings).grid(row=1, column=2, sticky="w",
                                                         pady=4)
            self.kill_status = tk.StringVar(value="进入有敌方角色的战斗后自动执行。")
            ttk.Label(killbox, textvariable=self.kill_status, wraplength=520,
                      justify="left").grid(row=2, column=0, columnspan=3, sticky="w",
                                           padx=8, pady=(0, 6))

            self.status = tk.StringVar(
                value="游戏运行后选择进程点击“启动”；换局自动继续，取消勾选会恢复原值。")
            ttk.Label(root, textvariable=self.status, wraplength=520,
                      justify="left").pack(fill="x", padx=12, pady=(4, 12))

            self.load_settings()
            self.refresh()
            root.after(100, self.tick)
            root.after(30, self.auto_loop)  # C++ 版 20ms 定时器驱动，30ms 足够接近
            root.after(1000, self.refresh)
            root.protocol("WM_DELETE_WINDOW", self.on_close)

        # -- 设置持久化 --
        def load_settings(self):
            path = settings_path()
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as fp:
                    data = json.load(fp)
            except (OSError, ValueError):
                return
            items = data.get("features", [])
            for i, f in enumerate(self.features):
                item = items[i] if i < len(items) else {}
                enabled, entry, _value = self.rows[i]
                enabled.set(bool(item.get("enabled", False)))
                state = entry.cget("state")
                entry.configure(state="normal")
                entry.delete(0, "end")
                entry.insert(0, str(item.get("value", f.initial)))
                entry.configure(state=state)
            self.kill_var.set(bool(data.get("kill", False)))
            self.kill_delay.set(str(data.get("kill_delay", "0")))
            self.kill_armed_at = 0  # 等 actor 检测到后再武装
            self.suicide_var.set(bool(data.get("suicide", False)))
            self.suicide_delay.set(str(data.get("suicide_delay", "10")))
            self.suicide_armed_at = 0  # 等 actor 检测到后再武装

        def save_settings(self):
            path = settings_path()
            if not path:
                return
            data = {"features": [{"enabled": self.rows[i][0].get(),
                                  "value": self.rows[i][1].get()}
                                 for i in range(len(self.features))],
                    "kill": self.kill_var.get(),
                    "kill_delay": self.kill_delay.get(),
                    "suicide": self.suicide_var.get(),
                    "suicide_delay": self.suicide_delay.get()}
            try:
                with open(path, "w", encoding="utf-8") as fp:
                    json.dump(data, fp, ensure_ascii=False, indent=1)
            except OSError:
                pass

        # -- 进程列表 --
        def selected_pid(self):
            index = self.combo.current()
            if 0 <= index < len(self.pids):
                return self.pids[index]
            return 0

        def refresh(self):
            self.root.after(1000, self.refresh)  # 先续约：下方任何分支提前返回都不中断刷新
            found = find_processes()
            if [pid for pid, _name in found] == self.pids:
                return
            if not found and LAST_SNAP_ERROR:
                self.status.set(LAST_SNAP_ERROR)
            preferred = self.selected_pid()
            self.pids = [pid for pid, _name in found]
            self.combo["values"] = [f"{name}  ·  PID {pid}" for pid, name in found]
            index = -1
            if preferred:
                index = next((i for i, pid in enumerate(self.pids) if pid == preferred), -1)
            elif len(self.pids) == 1:
                index = 0
            if index >= 0:
                self.combo.current(index)
            else:
                self.combo.set("")

        # -- 连接与断开 --
        def connect(self):
            pid = self.selected_pid()
            if self.handle:
                if k32.GetProcessId(self.handle) == pid and \
                        k32.WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT:
                    self.status.set("当前进程已启动，勾选功能会自动执行，无需重复启动。")
                    return
                if not self.stop(silent=True):
                    return
            if not pid:
                self.status.set("列表自动刷新；请先打开游戏并选择进程。")
                return
            handle = k32.OpenProcess(PROCESS_RIGHTS, False, pid) or 0
            if not handle:
                error = ctypes.get_last_error()
                if error == 5:
                    self.status.set("无法打开进程（拒绝访问）。若游戏以管理员运行，"
                                    "请同样以管理员运行本脚本。")
                else:
                    self.status.set(f"无法打开进程（错误码 {error}）。")
                return
            path = query_image_path(handle)
            digest = file_sha256(path) if path else ""
            note = ""
            if digest not in CLIENT_HASHES:
                # 应用户要求：未知客户端只警告不拦截。
                note = "（未核对版本：属性可能无效甚至闪退；秒杀受序言检查保护会自动拒绝）"
            base = module_base(pid) or BASE_FALLBACK
            self.handle, self.base, self.actor = handle, base, None
            self.auto_fault = False
            self.status.set(f"已启动{note}。沿用勾选设置，换局自动继续，无需重复连接。")

        def stop_clicked(self):
            self.stop()

        def stop(self, silent=False):
            if not self.handle:
                if not silent:
                    self.status.set("尚未连接游戏进程。")
                return True
            self.kill_cancel = True
            if self.kill_busy():
                # 不强杀线程：等当前原生调用返回后再断开（kill.h 同款语义）
                self.disconnect_pending = True
                if not silent:
                    self.status.set("等待秒杀调用结束后断开；勾选已保留。")
                return False
            if k32.WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0:
                self.actor = None  # 游戏已退出，原值无法也无需恢复
            if not self.restore_all():
                self.status.set("恢复原值失败，请保持游戏运行后重试停止。")
                return False
            k32.CloseHandle(self.handle)
            self.handle, self.base, self.actor = 0, 0, None
            self.auto_fault = False
            self.disconnect_pending = False
            for _enabled, _entry, value in self.rows:
                value.set("—")
            if not silent:
                self.status.set("已停止并断开，勾选已保留。")
            return True

        def restore_all(self):
            ok = True
            for f in self.features:
                if not feature_restore(self.handle, self.actor, f):
                    ok = False
            return ok

        # -- 周期执行 --
        def tick(self):
            if self.handle:
                if k32.WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0:
                    self.actor = None  # 游戏已退出：不回写旧内存
                    self.disconnect_pending = True
                elif self.disconnect_pending and not self.kill_busy():
                    self.disconnect_pending = False
                    if self.stop(silent=True):
                        self.status.set("游戏已退出，已停止所有操作；勾选保留。")
                elif not self.disconnect_pending:
                    self.enforce()
            self.root.after(100, self.tick)

        def enforce(self):
            manager = read_u32(self.handle, self.base + MANAGER_PTR)
            info = read_u32(self.handle, self.base + INFO_PTR)
            uid = read_u64(self.handle, info + 0x18) if info else 0
            actor = resolve_actor(self.handle, manager, uid) if manager and uid else None
            if not actor or not actor[1]:
                self.actor = None
                self.restore_all()
                for _enabled, _entry, value in self.rows:
                    value.set("—")
                self.status.set("等待自己的战斗角色。大厅、载入或离开战斗时停止修改。")
                return
            if actor != self.actor:
                self.actor = None  # 换局：旧内存不回写，仅清除标记
                self.restore_all()
                self.actor = actor
            error = False
            for i, f in enumerate(self.features):
                enabled, entry, value = self.rows[i]
                current = feature_current(self.handle, actor, f)
                if current is None:
                    error = True
                    continue
                value.set(format_value(current, f.is_int))
                if not enabled.get():
                    if not feature_restore(self.handle, actor, f):
                        error = True
                    continue
                desired, ok = feature_desired(entry.get(), f)
                if not ok:
                    feature_restore(self.handle, actor, f)
                    error = True
                    continue
                if not f.saved:
                    f.original, f.last, f.saved = current, current, True
                if write_u32(self.handle, feature_address(actor, f), desired):
                    f.last = desired
                else:
                    error = True
            if error:
                self.status.set("部分功能本轮未写入：数值须为 0–999，或角色状态已变化；下轮自动重试。")
            else:
                self.status.set("已启动 · 每 100 毫秒执行勾选功能；取消勾选恢复原值。")

        # -- 自动战斗（移植 kill.h 的 startKill/pollKill/autoTick）--
        def kill_busy(self):
            return self.kill_job.busy() or self.kill_next < len(self.kill_queue)

        def poll_kill(self):
            if not self.kill_busy():
                return
            if self.kill_job.busy():
                result = self.kill_job.poll(self.handle)
                if result == -1:
                    if time.monotonic() - self.kill_job.started > 5.0:
                        self.kill_cancel = True
                        self.auto_fault = True
                        self.kill_status.set("调用超时：自动操作已暂停，等待当前调用返回；不强杀线程。")
                    return
                target = self.current_target
                if target and result == 1:
                    self.kill_done += 1
                else:
                    self.kill_skipped += 1
                    if result == 2:
                        self.round_reasons["预检跳过"] = self.round_reasons.get("预检跳过", 0) + 1
                    elif result == 4:
                        self.round_reasons["原生拒绝"] = self.round_reasons.get("原生拒绝", 0) + 1
                    elif result != -2:
                        self.round_reasons[f"调用异常({result})"] = 1
                        self.kill_cancel = True
                        self.auto_fault = True
                self.current_target = None
            while not self.kill_cancel and self.kill_next < len(self.kill_queue):
                actor = self.kill_queue[self.kill_next]
                self.kill_next += 1
                if not self.kill_var.get():
                    self.kill_skipped += 1
                    continue
                k = make_kill(self.handle, self.base, self.actor, actor,
                              self.round_reasons) if self.actor else None
                if not k:
                    self.kill_skipped += 1
                    continue
                if not self.kill_job.start(self.handle, k):
                    self.kill_cancel = True
                    self.auto_fault = True
                    self.kill_skipped += 1
                    break
                self.current_target = actor
                return
            self.kill_queue.clear()
            self.kill_next = 0
            if self.auto_fault:
                err = self.kill_job.start_error
                if err:
                    self.kill_status.set(
                        f"自动操作暂停：远程线程创建失败（Win32 错误码 {err}）。"
                        "勾选已保留；处理后重新连接恢复。")
                else:
                    self.kill_status.set("自动操作因调用失败/异常暂停。勾选已保留；检查后重新连接恢复。")
                return
            self.kill_status.set(
                round_summary(self.kill_done, self.kill_skipped,
                              self.round_reasons, self.kill_cancel))

        def on_suicide_toggle(self):
            # 起算点不在这里：由 auto_tick 在检测到角色地址后武装计时，换局/取消即作废
            self.suicide_armed_at = 0
            self.save_settings()

        def arm_delay(active, armed):
            """延迟起算：检测到角色地址才武装计时；勾选取消或角色消失即作废。"""
            if self.actor and active and not armed:
                return now_ms()
            if (not active or not self.actor) and armed:
                return 0
            return armed

        def start_kill(self):
            if self.kill_busy() or self.auto_fault:
                return
            if not self.handle or not self.actor or not self.actor[1]:
                self.kill_status.set("请先启动，并进入战斗。")
                return
            manager = read_u32(self.handle, self.base + MANAGER_PTR)
            ok, actors = list_actors(self.handle, manager) if manager else (False, [])
            if not ok:
                self.kill_status.set("请先启动，并进入战斗。")
                return
            self.kill_queue.clear()
            self.kill_next = self.kill_done = self.kill_skipped = 0
            self.kill_cancel = False
            self.round_reasons = {}
            # 自杀：一次性调用，角色死亡后 0x7C 检查会自然拒绝，不会反复自残
            # 延迟未到时跳过自杀但继续秒杀，两者互不阻塞
            notes = ""
            if self.suicide_var.get():
                delay_ms = parse_delay_ms(self.suicide_delay.get())
                elapsed = now_ms() - self.suicide_armed_at
                if elapsed < delay_ms:
                    notes += ("自杀将在 %d 秒后执行；"
                              % ((delay_ms - elapsed + 999) // 1000))
                else:
                    k = make_kill(self.handle, self.base, self.actor, self.actor,
                                  self.round_reasons, suicide=True)
                    if k and self.kill_job.start(self.handle, k):
                        self.current_target = self.actor
                        self.kill_status.set("正在执行自杀调用；上一轮未结束时不重复创建任务。")
                        return
                    self.kill_skipped += 1
                    if k:
                        self.kill_cancel = True
                        self.auto_fault = True
                    elif self.round_reasons.get("自身未激活"):
                        self.suicide_armed_at = 0  # 角色已死：复活后重新计延迟
            kill_hold = ""
            if self.kill_var.get():
                delay_ms = parse_delay_ms(self.kill_delay.get())
                elapsed = now_ms() - self.kill_armed_at
                if elapsed < delay_ms:
                    kill_hold = ("秒杀将在 %d 秒后开始；"
                                 % ((delay_ms - elapsed + 999) // 1000))
            for a in actors:
                if self.kill_var.get() and not kill_hold:
                    k = make_kill(self.handle, self.base, self.actor, a,
                                  self.round_reasons)
                    if k:
                        self.kill_queue.append(a)
            if not self.kill_queue:
                self.kill_status.set("已勾选，等待可操作目标；" + notes + kill_hold +
                                     round_summary(0, 0, self.round_reasons, False))
                return
            self.kill_status.set("正在执行；上一轮未结束时不重复创建任务。" + kill_hold)
            self.poll_kill()

        def auto_tick(self):
            self.poll_kill()
            # 自杀/秒杀延迟起算点：检测到角色地址（进入战斗）才开始计时；角色消失重新武装
            self.suicide_armed_at = self.arm_delay(self.suicide_var.get(),
                                                   self.suicide_armed_at)
            self.kill_armed_at = self.arm_delay(self.kill_var.get(),
                                                self.kill_armed_at)
            wanted = self.kill_var.get() or self.suicide_var.get()
            if wanted and self.actor and \
                    round_due(now_ms(), self.last_round, self.kill_busy(),
                              self.auto_fault or self.disconnect_pending, wanted):
                self.last_round = now_ms()
                self.start_kill()

        def auto_loop(self):
            # 秒杀独立 30ms 循环（C++ 版为 20ms 定时器），不随属性 tick 变慢
            if self.handle:
                self.auto_tick()
            self.root.after(30, self.auto_loop)

        def on_close(self):
            self.save_settings()
            if self.handle and not self.stop(silent=True):
                self.status.set("恢复原值失败，请保持游戏运行后再关闭本窗口重试。")
                return
            self.root.destroy()

    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        return self_test()
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
