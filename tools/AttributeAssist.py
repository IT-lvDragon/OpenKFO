"""gfxz/gfld 单机属性助手（外置版：跨进程读写 + 一次性远程线程，无 DLL 注入）。

移植自 tools/game-mod/main.cpp 与 kill.h：
- 属性：怒气倍率/无敌/霸体/反伤/防御/吸血，每 100ms 执行勾选项，取消勾选恢复原值。
- 秒杀：每 400ms 一轮，枚举敌方角色后逐个经一次性远程线程调用原生发包/伤害函数。
- 结算重放：钩住发包函数抓包（E9 跳板 + 环形槽），改字节后经原生 send 原样重发。
- 版本校验：已知 gfxz.dat 哈希直接放行；其他客户端（gfld.dat 或更新版）仅警告不拦截，
  秒杀仍受函数序言检查保护（序言不符自动拒绝），属性写入无保护，风险自负。
"""
import ctypes
import json
import os
import random
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
k32.TerminateThread.argtypes = [_handle, wintypes.DWORD]
k32.TerminateThread.restype = wintypes.BOOL
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
k32.Module32NextW = getattr(k32, "Module32NextW", None)
if k32.Module32NextW:
    k32.Module32NextW.argtypes = [_handle, ctypes.POINTER(MODULEENTRY32W)]
    k32.Module32NextW.restype = wintypes.BOOL


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

MODULE_LOOKUP_INFO = ""     # module_base_named 最近一次查找过程诊断


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
    """主模块（游戏 exe）基址：toolhelp 模块快照取首模块（旧行为，实测可用）；
    失败返回 0，由调用方 BASE_FALLBACK(0x400000) 兜底。EnumProcessModulesEx
    仅作诊断对比写入 MODULE_LOOKUP_INFO（不采用其返回值：用户机器实测该
    路径返回错误基址，采用后所有偏移失效）。"""
    global MODULE_LOOKUP_INFO
    base = 0
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) or 0
    if snap:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if k32.Module32FirstW(snap, ctypes.byref(entry)):
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
        k32.CloseHandle(snap)
    info = "toolhelp=0x%08X" % base if base else "toolhelp失败(err=%d)" % ctypes.get_last_error()
    handle = k32.OpenProcess(PROCESS_RIGHTS, False, pid) or 0
    if handle:
        ebase = _enum_modules32(handle, "")
        k32.CloseHandle(handle)
        info += " enum32=0x%08X" % ebase if ebase else " enum32无"
    MODULE_LOOKUP_INFO = info
    return base


def module_base_named(pid, name, handle=0):
    """枚举进程模块找指定 DLL 的加载基址（小写比较）；找不到返回 0。
    先 toolhelp（Module32First/NextW），失败/没找到再用 EnumProcessModulesEx
    的 32 位模块列表兜底；过程诊断写入 MODULE_LOOKUP_INFO。"""
    global MODULE_LOOKUP_INFO
    MODULE_LOOKUP_INFO = ""
    base = 0
    count = 0
    if k32.Module32NextW:
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) or 0
        if snap:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            if k32.Module32FirstW(snap, ctypes.byref(entry)):
                while True:
                    count += 1
                    if (entry.szModule or "").lower() == name.lower():
                        base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0
                        break
                    if not k32.Module32NextW(snap, ctypes.byref(entry)):
                        break
            else:
                MODULE_LOOKUP_INFO = "toolhelp首模块失败(err=%d)" % ctypes.get_last_error()
            k32.CloseHandle(snap)
        else:
            MODULE_LOOKUP_INFO = "toolhelp快照失败(err=%d)" % ctypes.get_last_error()
        if base:
            MODULE_LOOKUP_INFO = "toolhelp=%d" % count
            return base
    if not handle:
        MODULE_LOOKUP_INFO += " 未找到(%d模块)" % count
        return 0
    MODULE_LOOKUP_INFO += " toolhelp=%d模块" % count
    enum = _enum_modules32_base(handle, name)
    if enum:
        MODULE_LOOKUP_INFO += " enum32命中"
        return enum
    return 0


def _enum32_fns():
    """EnumProcessModulesEx/GetModuleBaseNameW 函数对：kernel32 的 K32 前缀导出
    优先（Win7+），缺失时回落 psapi.dll；都不可用返回 (None, None)。"""
    fn_enum = getattr(k32, "K32EnumProcessModulesEx", None)
    fn_name = getattr(k32, "K32GetModuleBaseNameW", None)
    if fn_enum is None or fn_name is None:
        try:
            psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)
            fn_enum = psapi.EnumProcessModulesEx
            fn_name = psapi.GetModuleBaseNameW
        except OSError:
            return None, None
    return fn_enum, fn_name


def _enum_modules32(handle, name):
    """EnumProcessModulesEx(LIST_MODULES_32BIT) 枚举目标 32 位模块：
    name 为空返回首个模块（即 exe）基址，否则按名称（小写）匹配。
    诊断追加进 MODULE_LOOKUP_INFO；找不到返回 0。"""
    fn_enum, fn_name = _enum32_fns()
    if fn_enum is None:
        MODULE_LOOKUP_INFO += " psapi不可用"
        return 0
    fn_enum.argtypes = [_handle, ctypes.POINTER(_handle), wintypes.DWORD,
                        ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    fn_enum.restype = wintypes.BOOL
    fn_name.argtypes = [_handle, _handle, ctypes.c_wchar_p, wintypes.DWORD]
    fn_name.restype = wintypes.DWORD
    mods = (_handle * 1024)()
    need = wintypes.DWORD(0)
    if not fn_enum(handle, mods, ctypes.sizeof(mods), ctypes.byref(need), 0x01):
        MODULE_LOOKUP_INFO += " enum32失败(err=%d)" % ctypes.get_last_error()
        return 0
    n = min(1024, need.value // ctypes.sizeof(_handle))
    MODULE_LOOKUP_INFO += " enum32=%d模块" % n
    buf = ctypes.create_unicode_buffer(260)
    for i in range(n):
        if name:
            if fn_name(handle, mods[i], buf, 260) and buf.value.lower() == name.lower():
                return mods[i] or 0
        elif mods[i]:
            return mods[i]
    return 0


def _enum_modules32_base(handle, name):
    """EnumProcessModulesEx(仅 32 位模块) 兜底：64 位工具进程枚举 WOW64
    目标的模块列表；诊断追加进 MODULE_LOOKUP_INFO，找不到返回 0。"""
    return _enum_modules32(handle, name)


def resolve_export(handle, base, name):
    """远程解析 32 位 PE 导出表拿函数 RVA；找不到/转发导出/解析失败返回 0。"""
    dos = read_mem(handle, base, 0x40)
    if not dos or len(dos) < 0x40:
        return 0
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if not 0x40 <= e_lfanew < 0x1000:
        return 0
    nt = read_mem(handle, base + e_lfanew, 0x120)
    if not nt or len(nt) < 0x78 or nt[:4] != b"PE\x00\x00":
        return 0
    exp_rva, exp_size = struct.unpack_from("<II", nt, 4 + 20 + 96)   # DataDirectory[0]
    if not exp_rva or exp_rva >= 0x80000000:
        return 0
    d = read_mem(handle, base + exp_rva, 40)
    if not d or len(d) < 40:
        return 0
    num_names, = struct.unpack_from("<I", d, 24)
    names_rva, = struct.unpack_from("<I", d, 32)
    ords_rva, = struct.unpack_from("<I", d, 36)
    if not num_names or num_names > 0x10000:
        return 0
    nm = read_mem(handle, base + names_rva, 4 * num_names)
    if not nm:
        return 0
    for i in range(num_names):
        rva, = struct.unpack_from("<I", nm, 4 * i)
        s = read_mem(handle, base + rva, 16)
        if s and s.split(b"\x00")[0] == name.encode():
            od = read_mem(handle, base + ords_rva + 2 * i, 2)
            if not od:
                return 0
            idx, = struct.unpack("<H", od)
            fv = read_mem(handle, base + struct.unpack_from("<I", d, 28)[0] + 4 * idx, 4)
            if not fv:
                return 0
            rva, = struct.unpack("<I", fv)
            if exp_rva <= rva < exp_rva + exp_size:   # 落在导出目录内 = 转发串
                return 0
            return rva
    return 0


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


def parse_ms(text, default, cap=3600 * 1000):
    """毫秒输入解析（与 parse_delay_ms 的“秒”语义区分）：空回退默认；非法回退默认；
    负数归零；上限封顶。"""
    text = str(text).strip()
    if not text:
        return default
    try:
        value = int(float(text))
    except ValueError:
        return default
    return max(0, min(value, cap))


def arm_delay(actor_ready, active, armed):
    """延迟起算：检测到角色地址且勾选后才开始计时；取消勾选或角色消失即作废。"""
    if actor_ready and active and not armed:
        return now_ms()
    if (not active or not actor_ready) and armed:
        return 0
    return armed


# ---- 自动跑图（键盘模拟）+ 自动点击（鼠标模拟）：SendInput 前台注入，不写内存 ----
MOVE_KEYS = {"右(D)": 0x44, "左(A)": 0x41, "上(W)": 0x57, "下(S)": 0x53,
             "右(→)": 0x27, "左(←)": 0x25, "上(↑)": 0x26, "下(↓)": 0x28}
_u32 = None


def user32():
    """user32 惰性绑定（仅 Windows 实际调用；自检与 Linux 脚手架不触发）。"""
    global _u32
    if _u32 is None:
        _u32 = ctypes.WinDLL("user32.dll", use_last_error=True)
        _u32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT),
                                   ctypes.c_int]
        _u32.SendInput.restype = wintypes.UINT
        _u32.IsWindow.argtypes = [wintypes.HWND]
        _u32.IsWindowVisible.argtypes = [wintypes.HWND]
        _u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND,
                                                  ctypes.POINTER(wintypes.DWORD)]
        _u32.EnumWindows.argtypes = [
            ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM),
            wintypes.LPARAM]
        _u32.GetForegroundWindow.restype = wintypes.HWND
        _u32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        _u32.SetCursorPos.argtypes = [wintypes.LONG, wintypes.LONG]
        _u32.SetCursorPos.restype = wintypes.BOOL
    return _u32


def find_main_window(pid):
    """取该进程第一个可见顶层窗口，作为跑图按键与点击的前台判定目标。"""
    if not pid:
        return 0
    lib = user32()
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _lp):
        owner = wintypes.DWORD()
        lib.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and lib.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False
        return True

    lib.EnumWindows(cb, 0)
    return found[0] if found else 0


def game_foreground(pid):
    """前台窗口是否属于该进程；模拟输入只投递给前台，避免打进别的程序。
    按进程 ID 判定而非窗口句柄严格比对：游戏常有多个顶层窗口，枚举到的
    第一个未必是玩家正在用的前台窗口，句柄比对会永远判为“不在前台”。"""
    if not pid:
        return False
    lib = user32()
    fg = lib.GetForegroundWindow()
    if not fg:
        return False
    owner = wintypes.DWORD()
    lib.GetWindowThreadProcessId(fg, ctypes.byref(owner))
    return owner.value == pid


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG))]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG))]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("union", _INPUTUNION)]


KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE = 0x0001, 0x0002, 0x0008
MAPVK_VK_TO_VSC = 0
EXTENDED_VKS = {0x25, 0x26, 0x27, 0x28}  # ←↑→↓


def kb_scancode(vk):
    """虚键码 → 扫描码（DirectInput 游戏轮询的是扫描码）。"""
    lib = user32()
    lib.MapVirtualKeyW.argtypes = [wintypes.UINT, wintypes.UINT]
    lib.MapVirtualKeyW.restype = wintypes.UINT
    return lib.MapVirtualKeyW(vk, MAPVK_VK_TO_VSC)


def kb_flags(vk, down):
    """SendInput 标志（扫描码模式）：8=按扫描码注入，1=扩展键，2=抬起。"""
    flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if vk in EXTENDED_VKS else 0)
    return flags if down else flags | KEYEVENTF_KEYUP


def send_move_key(hwnd, vk, down):
    """SendInput 注入键盘事件——扫描码模式（DirectInput 老游戏只认扫描码）。
    仅当游戏窗口为前台时由 move_tick 调用；hwnd 供前台比对。"""
    lib = user32()
    inp = INPUT(type=1)  # INPUT_KEYBOARD
    inp.union.ki.wScan = kb_scancode(vk)
    inp.union.ki.dwFlags = kb_flags(vk, down)
    return lib.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT)) == 1


MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_RIGHTDOWN = 0x0002, 0x0008


def mouse_flags(button, down):
    """鼠标事件标志：按下取 DOWN 值，抬起 = 按下 << 1（LEFTUP=4 / RIGHTUP=0x10）。"""
    base = MOUSEEVENTF_RIGHTDOWN if button == "右键" else MOUSEEVENTF_LEFTDOWN
    return base if down else base << 1


def jitter_point(x, y, radius):
    """区域内随机取点：半径 0 即精确点；半径 r 时落在以 (x,y) 为中心的方形内。"""
    if radius <= 0:
        return x, y
    return x + random.randint(-radius, radius), y + random.randint(-radius, radius)


def send_mouse_click(x, y, button="左键"):
    """SetCursorPos 定位 + SendInput 按下/抬起。不走 MOUSEEVENTF_ABSOLUTE：
    其 0..65535 归一化按物理像素解释，DPI 缩放/多屏时与 GetCursorPos 拾取的
    逻辑坐标错位；SetCursorPos 与拾取同处一个坐标空间，点到即拾取点。"""
    lib = user32()
    if not lib.SetCursorPos(int(x), int(y)):
        return False
    down = INPUT(type=0)  # INPUT_MOUSE
    down.union.mi.dwFlags = mouse_flags(button, True)
    up = INPUT(type=0)
    up.union.mi.dwFlags = mouse_flags(button, False)
    events = (INPUT * 2)(down, up)
    return lib.SendInput(2, events, ctypes.sizeof(INPUT)) == 2


def parse_pixels(text, default=0):
    """点击随机范围解析：像素；空/非法回退默认；负数归零，上限 2000。"""
    text = str(text).strip()
    if not text:
        return default
    try:
        value = int(float(text))
    except ValueError:
        return default
    return max(0, min(value, 2000))


_psapi = None


def psapi():
    """psapi 惰性绑定：EmptyWorkingSet 裁剪目标进程工作集（仅 Windows 实际调用）。"""
    global _psapi
    if _psapi is None:
        _psapi = ctypes.WinDLL("psapi.dll", use_last_error=True)
        _psapi.EmptyWorkingSet.argtypes = [_handle]
        _psapi.EmptyWorkingSet.restype = wintypes.BOOL
    return _psapi


def parse_minutes(text, default=10):
    """自动清理间隔解析：分钟；空/非法回退默认；范围 1–1440。"""
    text = str(text).strip()
    if not text:
        return default
    try:
        value = int(float(text))
    except ValueError:
        return default
    return max(1, min(value, 1440))


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
    """一次性远程线程调用，结束后回收内存；超过 5 秒未完成则强杀线程回收资源。"""

    TIMEOUT_SECONDS = 5.0

    def __init__(self):
        self.thread = 0
        self.block = 0
        self.started = 0.0
        self.start_error = 0
        self.timed_out = False

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
        self.timed_out = False
        if k32.WaitForSingleObject(self.thread, 0) != WAIT_OBJECT_0:
            # 正常未完成不释放；但超过 5 秒未返回说明原生函数卡死，强杀线程回收资源
            if time.monotonic() - self.started < self.TIMEOUT_SECONDS:
                return -1
            self.timed_out = True
            k32.TerminateThread(self.thread, 0)
        result = read_u32(handle, self.block + 4096 + 128) or 0
        k32.CloseHandle(self.thread)
        self.thread = 0
        k32.VirtualFreeEx(handle, ctypes.c_void_p(self.block), 0, MEM_RELEASE)
        self.block = 0
        return result if not self.timed_out else -3


# ---- 结算重放：钩住发包函数抓包，改字节后经原生 send 原样重发 ----
HOOK_CTR_OFF = 0        # 抓包数据块：发包计数器（游戏线程 lock xadd 递增）
HOOK_MARKER_OFF = 4     # 抓包数据块：重放标记（重放线程置 1，钩子记录进槽）
HOOK_SLOTS_OFF = 8      # 槽区起点
HOOK_SLOT_HDR = 24      # 槽头：id(4) + len(4) + a2(4) + a3(4) + a4(4) + meta(4)
HOOK_SLOT_DATA = 1000   # 槽内包体上限
HOOK_SLOT_SIZE = 1024   # 槽总大小（2 的幂，stub 用 shl 10 寻址）
HOOK_SLOTS = 64         # 环形槽数；两次轮询之间超过 64 包会丢最旧的
HOOK_READ_BYTES = 16    # 入口序言检查需读取的字节数
HOOK_PROBE_CAP = 64     # len 未知函数（大厅B）的启发式拷贝上限，防越界读

# 发送函数族（cdecl，id 恒为 arg1；buf/len 位置已用调用方压栈序列逐一核实）：
#   大厅 A 0x63C950 (id, 0, buf, len)    大厅 B 0x63CA00 (id, buf 或 0)
#   战斗 A 0x63FBB0 (id, buf, len, 0, 0) 战斗 C 0x63FB40 (id, buf, len, 0, 0)
# (rva, 名称, len_arg, buf_arg)：stub 从第几个参数取拷贝长度/包体指针；
# len_arg=0 表示长度未知（大厅B），用 a3→a4 启发式并夹到 HOOK_PROBE_CAP。
SEND_FUNCS = (
    (0x63C950, "大厅A", 4, 3),
    (0x63CA00, "大厅B", 0, 2),
    (KILL_SEND_OFF, "战斗A", 3, 2),
    (0x63FB40, "战斗C", 3, 2),
)
FN_NAMES = {rva: name for rva, name, _l, _b in SEND_FUNCS}
MAIN_A_OFF = 0x63C950
MAIN_B_OFF = 0x63CA00
SEND_C_OFF = 0x63FB40

_ONE_BYTE_OPS = (set(range(0x40, 0x50)) | set(range(0x50, 0x60)) |
                 {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F,
                  0x60, 0x61, 0x90, 0x98, 0x99, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
                  0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
                  0xF5, 0xF8, 0xF9, 0xFC, 0xFD} |
                 set(range(0x6C, 0x70)) | {0xEC, 0xED, 0xEE, 0xEF})
_RELATIVE_OPS = (set(range(0x70, 0x80)) | {0xE0, 0xE1, 0xE2, 0xE3, 0xEA,
                                           0xEB, 0xC3, 0xC2, 0xCB, 0xCC, 0xCD})


def _modrm_extra(buf, i):
    """ModRM 位于 buf[i] 时其后附带字节数（SIB/位移）；越界返回 None。"""
    if i >= len(buf):
        return None
    mod = buf[i] >> 6
    rm = buf[i] & 7
    j = i + 1
    if mod != 3 and rm == 4:
        if j >= len(buf):
            return None
        sib = buf[j]
        j += 1
        if mod == 0 and sib & 7 == 5:
            j += 4                      # SIB base=101 → disp32
    elif mod == 0 and rm == 5:
        j += 4                          # disp32 无基址
    if mod == 1:
        j += 1
    elif mod == 2:
        j += 4
    return j - i


def instr_len32(buf):
    """估算 32 位代码一条指令的长度（编译器常用输出子集）。
    遇到相对转移/ret 等搬移后语义会变、或无法识别的指令时返回 None。"""
    i = 0
    while i < len(buf) and buf[i] in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67,
                                      0xF0, 0xF2, 0xF3):
        i += 1
    if i >= len(buf):
        return None
    op = buf[i]
    i += 1
    if op == 0x0F:
        if i >= len(buf):
            return None
        op2 = buf[i]
        i += 1
        if 0x80 <= op2 <= 0x8F or 0xC8 <= op2 <= 0xCF or \
                op2 in (0x05, 0x0B, 0x31, 0x34, 0x35, 0x77,
                        0xA0, 0xA1, 0xA2, 0xA3, 0xA8, 0xA9):
            return None                 # jcc/loop、syscall/rdtsc/cpuid/emms 等：拒绝
        extra = _modrm_extra(buf, i)
        return None if extra is None else i + extra
    if op in _ONE_BYTE_OPS:
        return i
    if op in (0xE8, 0xE9):
        return i + 4                    # call/jmp rel32：5 字节，搬移后可重定位
    if op in _RELATIVE_OPS:
        return None
    if op == 0x68 or 0xB8 <= op <= 0xBF or op in (0xA1, 0xA3):
        return i + 4                    # push imm32 / mov r,imm32 / mov acc,moffs
    if op == 0x6A:
        return i + 1
    if op in (0xF6, 0xF7):
        if i >= len(buf):
            return None
        imm = 1 if (buf[i] >> 3) & 7 < 2 else 0     # TEST 组带立即数
    elif op in (0x81, 0x69, 0xC7):
        imm = 4
    elif op in (0x83, 0x6B, 0xC0, 0xC1, 0xC6):
        imm = 1
    else:
        imm = 0
    extra = _modrm_extra(buf, i)
    return None if extra is None else i + extra + imm


def hook_stolen(raw, send_addr):
    """发包函数入口原始字节 → (可整体搬移的前缀, E8/E9 重定位表)。
    逐条解码到 ≥5 字节（上限 16），保证跳回地址落在真实指令边界；范围内的
    裸 E8/E9 相对转移记录 (偏移, 绝对目标) 交 hook_code 重定向（E9 thunk
    入口即整条 E9）；jcc/ret 等搬移后语义会变的指令返回 None。"""
    if not raw or len(raw) < HOOK_READ_BYTES:
        return None
    raw = bytes(raw[:HOOK_READ_BYTES])
    n = 0
    relocs = []
    while n < 5:
        ln = instr_len32(raw[n:])
        if not ln:
            return None
        if raw[n] in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", raw, n + 1)[0]
            relocs.append((n, (send_addr + n + 5 + rel) & 0xFFFFFFFF))
        n += ln
        if n > 16:
            return None
    return bytes(raw[:n]), tuple(relocs)


def hook_code(code_base, data_base, send_addr, stolen, relocs, len_arg, buf_arg):
    """抓包钩子：记录 (id, a2, a3, a4) 与拷贝长度到环形槽，执行被覆盖的原指令
    （E8/E9 已按新地址重定位）后跳回边界。len_arg=长度参数序号（0=启发式），
    buf_arg=包体参数序号；buf 为 NULL 时只记槽头不拷贝。
    数据块：+0 计数器，+4 重放标记，+8 起 64×1024 槽（头 24 字节 + 包体）。"""
    c = Code32()
    c.bytes_((0x9C, 0x60))                          # pushfd/pushad：参数在 [esp+40..]
    c.bytes_((0x8B, 0x44, 0x24, 0x28))              # mov eax,[esp+40] → a1=id
    c.bytes_((0x8B, 0x5C, 0x24, 0x2C))              # mov ebx,[esp+44] → a2
    c.bytes_((0x8B, 0x4C, 0x24, 0x30))              # mov ecx,[esp+48] → a3
    c.bytes_((0x8B, 0x54, 0x24, 0x34))              # mov edx,[esp+52] → a4
    if len_arg == 3:
        c.bytes_((0x8B, 0xE9))                      # mov ebp, a3
    elif len_arg == 4:
        c.bytes_((0x8B, 0xEA))                      # mov ebp, a4
    else:                                           # 启发式：a3 合法用 a3，否则 a4
        c.bytes_((0x8B, 0xE9))
        c.bytes_((0x81, 0xFD))                      # cmp ebp, HOOK_PROBE_CAP
        c.word(HOOK_PROBE_CAP)
        c.bytes_((0x76, 0x02))                      # jbe +2
        c.bytes_((0x33, 0xED))                      # xor ebp, ebp
        c.bytes_((0x85, 0xED))                      # test ebp, ebp
        c.bytes_((0x75, 0x0C))                      # jnz have（跳过 12 字节）
        c.bytes_((0x8B, 0xEA))                      # mov ebp, a4
        c.bytes_((0x81, 0xFD))
        c.word(HOOK_PROBE_CAP)
        c.bytes_((0x76, 0x02))
        c.bytes_((0x33, 0xED))
    c.bytes_((0x81, 0xFD))                          # cmp ebp, HOOK_SLOT_DATA
    c.word(HOOK_SLOT_DATA)
    c.bytes_((0x76, 0x05))                          # jbe +5
    c.bytes_((0xBD,))                               # mov ebp, HOOK_SLOT_DATA（夹到上限）
    c.word(HOOK_SLOT_DATA)
    if buf_arg == 3:
        c.bytes_((0x85, 0xC9))                      # test ecx, ecx（buf=a3）
    else:
        c.bytes_((0x85, 0xDB))                      # test ebx, ebx（buf=a2）
    c.bytes_((0x75, 0x02))                          # jnz +2
    c.bytes_((0x33, 0xED))                          # buf 为 NULL → 长度清零
    c.bytes_((0xBE, 0x01, 0x00, 0x00, 0x00))        # mov esi, 1
    c.bytes_((0xF0, 0x0F, 0xC1, 0x35))              # lock xadd [计数器], esi → esi=旧值
    c.word(data_base + HOOK_CTR_OFF)
    c.bytes_((0x83, 0xE6, 0x3F))                    # and esi, 63
    c.bytes_((0xC1, 0xE6, 0x0A))                    # shl esi, 10（×1024）
    c.bytes_((0x81, 0xC6))                          # add esi, 槽区
    c.word(data_base + HOOK_SLOTS_OFF)
    c.bytes_((0x89, 0x06))                          # mov [esi], eax → id
    c.bytes_((0x89, 0x6E, 0x04))                    # mov [esi+4], ebp → len
    c.bytes_((0x89, 0x5E, 0x08))                    # mov [esi+8], ebx → a2
    c.bytes_((0x89, 0x4E, 0x0C))                    # mov [esi+12], ecx → a3
    c.bytes_((0x89, 0x56, 0x10))                    # mov [esi+16], edx → a4
    c.bytes_((0xA1,))                               # mov eax, [重放标记]
    c.word(data_base + HOOK_MARKER_OFF)
    c.bytes_((0x89, 0x46, 0x14))                    # mov [esi+20], eax → meta
    c.bytes_((0xFC,))                               # cld
    c.bytes_((0x8D, 0x7E, 0x18))                    # lea edi, [esi+24]
    if buf_arg == 3:
        c.bytes_((0x8B, 0xF1))                      # mov esi, ecx（源=a3）
    else:
        c.bytes_((0x8B, 0xF3))                      # mov esi, ebx（源=a2）
    c.bytes_((0x8B, 0xCD))                          # mov ecx, ebp
    c.bytes_((0xF3, 0xA4))                          # rep movsb
    c.bytes_((0x61, 0x9D))                          # popad/popfd：与压栈 9C,60 严格逆序，
                                                    # 先弹 flags 会把 EDI 当 EFLAGS、把 EFLAGS 装进 ESP
    c.bytes_(tuple(stolen))                         # 被覆盖的原指令
    base_pos = len(c.b) - len(stolen)
    for off, target in relocs:                      # stolen 内 E8/E9 重定位到原目标
        rel = (target - code_base - base_pos - off - 5) & 0xFFFFFFFF
        struct.pack_into("<I", c.b, base_pos + off + 1, rel)
    c.bytes_((0xE9,))                               # jmp send+len(stolen)
    p = c.hole()
    c.rel(p, send_addr + len(stolen) - code_base)   # rel32 相对下一条指令，需扣除加载基址
    return bytes(c.b)


def recv_prologue_delta(stolen):
    """recv 序言白名单校验 → stolen 对 esp 的净变化（≤0）；不允许则 None。
    仅放行热补丁/帧指针类序言（mov edi,edi / push r32 / mov ebp,esp /
    sub esp,imm），保证 stub 能静态重建栈布局。"""
    if not stolen or len(stolen) < 5:
        return None
    raw = bytes(stolen)
    delta = 0
    n = 0
    while n < 5:
        ln = instr_len32(raw[n:])
        if not ln:
            return None
        op = raw[n]
        if op == 0x8B and raw[n + 1:n + 2] == b"\xff":       # mov edi,edi
            pass
        elif op == 0x8B and raw[n + 1:n + 2] == b"\xec":     # mov ebp,esp
            pass
        elif 0x50 <= op <= 0x57 and op != 0x54:              # push r32（不含 esp）
            delta -= 4
        elif op in (0x6A, 0x68):                             # push imm8/imm32
            delta -= 4
        elif op == 0x83 and raw[n + 1] == 0xEC:              # sub esp,imm8
            delta -= raw[n + 2]
        elif op == 0x81 and raw[n + 1] == 0xEC:              # sub esp,imm32
            delta -= struct.unpack_from("<I", raw, n + 2)[0]
        else:
            return None
        n += ln
        if n > 16:
            return None
    return delta


def _code32_push_esp_mem(c, off):
    """push dword [esp+off]（off ≤ 127 用 imm8，否则 imm32 形式）。"""
    if 0 <= off <= 127:
        c.bytes_((0xFF, 0x74, 0x24, off))
    else:
        c.bytes_((0xFF, 0xB4, 0x24))
        c.word(off)


def _code32_mov_ebp_esp_mem(c, off):
    """mov ebp,[esp+off]（同上双形式）。"""
    if 0 <= off <= 127:
        c.bytes_((0x8B, 0x6C, 0x24, off))
    else:
        c.bytes_((0x8B, 0xAC, 0x24))
        c.word(off)


def _code32_mov_esi_esp_mem(c, off):
    """mov esi,[esp+off]（同上双形式）。"""
    if 0 <= off <= 127:
        c.bytes_((0x8B, 0x74, 0x24, off))
    else:
        c.bytes_((0x8B, 0xB4, 0x24))
        c.word(off)


def recv_hook_code(code_base, data_base, body_addr, stolen, esp_delta):
    """recv 下行钩子 stub：原始栈执行 stolen（被覆盖的序言；入口是 E9 thunk 时
    stolen 为空、body_addr=真身入口）→ pushad → 垫参 call body_addr（stdcall
    自清 4 参）→ 返回值 >0 时把 buf 内容拷进环形槽（id=0xFFFFFFFF、meta=2
    标识下行）→ 恢复调用者 ebp/esp 后 ret 16。
    数据块布局与发送钩子一致（+0 计数器 / +4 重放标记 / +8 起 64×1024 槽）。"""
    c = Code32()
    if stolen:
        c.b += bytes(stolen)                            # 原始栈上执行序言（esp = E + esp_delta）
    c.bytes_((0x60,))                               # pushad → esp = E + esp_delta - 32
    base_off = 32 - esp_delta                       # 调用者返回地址相对当前 esp 的偏移
    for _ in range(4):                              # 压 flags/len/buf/s（stdcall 从右往左）；
        _code32_push_esp_mem(c, base_off + 16)      # 每次压栈后 esp-4，取参偏移同步 +4 → 恒定
    c.call(body_addr)                               # 真 recv 主体；返回后 eax=接收字节数
    c.bytes_((0x85, 0xC0, 0x7E))                    # test eax,eax / jle done
    jle_pos = c.hole()
    c.bytes_((0xBB, 0x01, 0x00, 0x00, 0x00))        # mov ebx,1
    c.bytes_((0xF0, 0x0F, 0xC1, 0x1D))              # lock xadd [计数器], ebx
    c.word(data_base + HOOK_CTR_OFF)
    c.bytes_((0x83, 0xE3, 0x3F))                    # and ebx,63
    c.bytes_((0xC1, 0xE3, 0x0A))                    # shl ebx,10
    c.bytes_((0x81, 0xC3))                          # add ebx,槽区
    c.word(data_base + HOOK_SLOTS_OFF)
    c.bytes_((0xC7, 0x03, 0xFF, 0xFF, 0xFF, 0xFF))  # [ebx]=0xFFFFFFFF 标识下行
    c.bytes_((0x89, 0x43, 0x04))                    # [ebx+4]=eax（收到字节数）
    c.bytes_((0xC7, 0x43, 0x08, 0, 0, 0, 0))        # a2/a3/a4=0
    c.bytes_((0xC7, 0x43, 0x0C, 0, 0, 0, 0))
    c.bytes_((0xC7, 0x43, 0x10, 0, 0, 0, 0))
    c.bytes_((0xC7, 0x43, 0x14, 2, 0, 0, 0))        # meta=2
    c.bytes_((0x8B, 0xC8))                          # mov ecx,eax
    c.bytes_((0x81, 0xF9))                          # cmp ecx,HOOK_SLOT_DATA
    c.word(HOOK_SLOT_DATA)
    c.bytes_((0x76, 0x02))                          # jbe +2
    c.bytes_((0xB9,))                               # mov ecx,HOOK_SLOT_DATA
    c.word(HOOK_SLOT_DATA)
    c.bytes_((0x8D, 0x7B, 0x18))                    # lea edi,[ebx+24]
    _code32_mov_esi_esp_mem(c, base_off + 8)        # mov esi,[esp+buf 偏移]（esp=esp0）
    c.bytes_((0xFC, 0xF3, 0xA4))                    # cld / rep movsb
    done = len(c.b)
    c.b[jle_pos] = (done - jle_pos - 1) & 0xFF
    c.bytes_((0x61,))                               # popad（esp 回到 E+esp_delta）
    if esp_delta <= -4:                             # 序言压过 ebp → 从栈上取回调用者 ebp
        _code32_mov_ebp_esp_mem(c, -esp_delta - 4)
    if esp_delta:
        c.bytes_((0x81, 0xC4))                      # add esp,-esp_delta → esp=E
        c.word(-esp_delta)
    c.bytes_((0xC2, 0x10, 0x00))                    # ret 16（recv stdcall 清 4 参）
    return bytes(c.b)


def send_packet_code(code_base, data_base, fn_addr, pushes, marker_addr):
    """远程线程：置重放标记 → 按 pushes 顺序压参调用 fn_addr（cdecl，序列中
    "BUF" 替换为包体地址 data_base）→ 清标记 → 写状态。
    data_base+0 为包体，+128 为状态：1 成功 / 2 SEH 捕获异常。marker_addr=0 不写标记。"""
    c = Code32()
    status = data_base + 128
    c.bytes_((0x55, 0x8B, 0xEC, 0x60, 0x83, 0xEC, 0x08))   # 帧 + pushad + SEH 节点
    c.bytes_((0xC7, 0x44, 0x24, 0x04))
    handler = c.hole()
    c.bytes_((0x64, 0xA1, 0, 0, 0, 0, 0x89, 0x04, 0x24, 0x64, 0x89, 0x25, 0, 0, 0, 0))
    if marker_addr:
        c.bytes_((0xC7, 0x05))
        c.word(marker_addr)
        c.word(1)
    for v in pushes:
        c.push(data_base if v == "BUF" else v)
    c.call(fn_addr)
    c.bytes_((0x83, 0xC4, 4 * len(pushes)))
    if marker_addr:
        c.bytes_((0xC7, 0x05))
        c.word(marker_addr)
        c.word(0)
    c.bytes_((0xC7, 0x05))                          # 状态 = 1（成功）
    c.word(status)
    c.word(1)
    c.bytes_((0xEB, 0x00))                          # jmp short cleanup
    over = len(c.b) - 1
    fault = len(c.b)
    if marker_addr:
        c.bytes_((0xC7, 0x05))                      # 异常路径也要清标记
        c.word(marker_addr)
        c.word(0)
    c.bytes_((0xC7, 0x05))                          # 状态 = 2（SEH 捕获）
    c.word(status)
    c.word(2)
    cleanup = len(c.b)
    c.b[over] = (cleanup - over - 1) & 0xFF
    c.bytes_((0x8B, 0x04, 0x24, 0x64, 0xA3, 0, 0, 0, 0, 0x83, 0xC4, 0x08, 0x61, 0x33,
              0xC0, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00))
    c.patch(handler, code_base + len(c.b))
    # SEH 处理器：恢复到 fault 处带 SEH 节点的栈位置继续执行（kill_code 同款）
    c.bytes_((0x8B, 0x44, 0x24, 0x0C, 0x8B, 0x54, 0x24, 0x08, 0x89, 0x90))
    c.word(0xC4)
    c.bytes_((0xC7, 0x80))
    c.word(0xB8)
    c.word(code_base + fault)
    c.bytes_((0x33, 0xC0, 0xC3))
    return bytes(c.b)


class PacketJob:
    """一次性远程线程重放数据包，结束后回收内存；5 秒未完成强杀线程回收资源。"""

    TIMEOUT_SECONDS = 5.0

    def __init__(self):
        self.thread = 0
        self.block = 0
        self.started = 0.0
        self.start_error = 0
        self.timed_out = False

    def busy(self):
        return bool(self.thread)

    def start(self, handle, fn_addr, pushes, payload, marker_addr=0):
        if self.thread:
            return False
        self.start_error = 0
        block = k32.VirtualAllocEx(handle, None, 8192, MEM_COMMIT_RESERVE, PAGE_READWRITE) or 0
        if not block:
            self.start_error = ctypes.get_last_error()
            return False
        code = send_packet_code(block, block + 4096, fn_addr, pushes, marker_addr)
        got = ctypes.c_size_t(0)
        ok = len(code) <= 4096
        if ok:
            ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(block), code,
                                             len(code), ctypes.byref(got))) \
                and got.value == len(code)
        if ok:
            ok = bool(k32.WriteProcessMemory(handle, ctypes.c_void_p(block + 4096),
                                             payload, len(payload),
                                             ctypes.byref(got))) and got.value == len(payload)
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
            return False
        self.thread, self.block, self.started = thread, block, time.monotonic()
        return True

    def poll(self, handle):
        if not self.thread:
            return -2
        self.timed_out = False
        if k32.WaitForSingleObject(self.thread, 0) != WAIT_OBJECT_0:
            if time.monotonic() - self.started < self.TIMEOUT_SECONDS:
                return -1
            self.timed_out = True
            k32.TerminateThread(self.thread, 0)
        result = read_u32(handle, self.block + 4096 + 128) or 0
        k32.CloseHandle(self.thread)
        self.thread = 0
        k32.VirtualFreeEx(handle, ctypes.c_void_p(self.block), 0, MEM_RELEASE)
        self.block = 0
        return result if not self.timed_out else -3


def parse_hex(text):
    """hex 文本 → bytes；支持空格/逗号/换行分隔；空或非法返回 None。"""
    clean = "".join(str(text).split()).replace(",", "")
    if not clean or len(clean) % 2:
        return None
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return None


def patch_hex(payload, find, replace):
    """把 payload 中所有 find 字节序列替换为 replace；find 为空返回 None。"""
    if not find or not payload:
        return None
    return payload.replace(find, replace)


def parse_filter_ids(text):
    """过滤条件：十进制或 0x 十六进制 ID 集合；无法解析的片段忽略。"""
    ids = set()
    for token in str(text).replace("，", ",").replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ids.add(int(token, 0))
        except ValueError:
            try:
                ids.add(int(token, 10))
            except ValueError:
                pass
    return ids


def pe_sections(hdr):
    """从 'PE\\0\\0' 签名起的头块 → [(节名, RVA, 虚拟大小, 特征)]；解析失败返回 []。"""
    if len(hdr) < 24 or hdr[:4] != b"PE\x00\x00":
        return []
    nsec = struct.unpack_from("<H", hdr, 6)[0]
    size_opt = struct.unpack_from("<H", hdr, 20)[0]
    off = 24 + size_opt
    out = []
    for i in range(nsec):
        raw = hdr[off + i * 40: off + (i + 1) * 40]
        if len(raw) < 40:
            break
        name = raw[:8].split(b"\x00")[0].decode("latin1").rstrip()
        vsize, va = struct.unpack_from("<II", raw, 8)
        chars = struct.unpack_from("<I", raw, 36)[0]
        out.append((name, va, vsize, chars))
    return out


def parse_capture_slot(blob):
    """1024 字节槽 → 记录；len 超上限按上限截断（写入端已截断，双保险）。
    marker 语义：0=游戏发送，1=工具重放回声，2=recv 下行（id=0xFFFFFFFF）。"""
    packet_id, n, a2, a3, a4, marker = struct.unpack_from("<6I", blob, 0)
    n = min(n, HOOK_SLOT_DATA)
    return {"id": packet_id, "a2": a2, "a3": a3, "a4": a4,
            "mine": marker == 1, "dir": marker,
            "data": bytes(blob[HOOK_SLOT_HDR:HOOK_SLOT_HDR + n])}


def packet_line(seq, rec):
    """列表行文本：序号 时间 id 长度 来源函数 收发 前八字节预览。"""
    data = rec["data"]
    if rec["id"] == 0xFFFFFFFF:
        source, tag = "recv↓", "下行"
    else:
        source = FN_NAMES.get(rec.get("fn", 0), "?")
        tag = "我发" if rec.get("mine") else "游戏"
    return "#%-4d %s id=%-6s len=%-4d [%s|%s] %s%s" % (
        seq, rec.get("time", ""), rec["id"] if rec["id"] != 0xFFFFFFFF else "recv",
        len(data), source, tag,
        data[:8].hex(" ").upper(), "…" if len(data) > 8 else "")


def replay_pushes(fn, packet_id, payload, a2=0, a3=0, a4=0):
    """按来源函数的参数表构造压栈序列（cdecl 从右往左压）；"BUF" 由
    send_packet_code 替换为包体地址。len 取捕获值（=包体长度）。
    战斗族 (id,buf,len,0,0)；大厅A (id,0,buf,len)；大厅B (id,buf 或 0)。"""
    buf = "BUF" if payload else a2
    if fn in (KILL_SEND_OFF, SEND_C_OFF):
        return (0, 0, len(payload), buf, packet_id)
    if fn == MAIN_A_OFF:
        return (len(payload), buf, a2, packet_id)
    return (buf, packet_id)


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

    # 延迟武装：actor 就绪且勾选才起算；取消勾选或角色失联即作废
    ok = ok and arm_delay(True, True, 0) > 0
    ok = ok and arm_delay(True, True, 123) == 123
    ok = ok and arm_delay(True, False, 123) == 0
    ok = ok and arm_delay(False, True, 123) == 0
    ok = ok and arm_delay(False, False, 0) == 0

    # 自动点击：鼠标事件标志（按下取 DOWN，抬起 = 按下 << 1）
    ok = ok and mouse_flags("左键", True) == 0x0002 \
        and mouse_flags("左键", False) == 0x0004
    ok = ok and mouse_flags("右键", True) == 0x0008 \
        and mouse_flags("右键", False) == 0x0010
    ok = ok and mouse_flags("中键", True) == 0x0002  # 未知按键回退左键

    # 自动跑图：方向键映射完整（WASD + 方向键两套）
    ok = ok and len(MOVE_KEYS) == 8 and MOVE_KEYS["右(D)"] == 0x44 \
        and MOVE_KEYS["左(A)"] == 0x41 and MOVE_KEYS["上(W)"] == 0x57 \
        and MOVE_KEYS["下(S)"] == 0x53 and MOVE_KEYS["右(→)"] == 0x27 \
        and MOVE_KEYS["左(←)"] == 0x25 and MOVE_KEYS["上(↑)"] == 0x26 \
        and MOVE_KEYS["下(↓)"] == 0x28

    # SendInput 键盘标志（扫描码模式）：8=SCANCODE，1=EXTENDEDKEY，2=KEYUP
    ok = ok and kb_flags(0x44, True) == 8 and kb_flags(0x44, False) == 10
    ok = ok and kb_flags(0x27, True) == 9 and kb_flags(0x27, False) == 11

    # 区域随机取点：半径 0 即精确点；半径 r 时必然落在 [-r, +r] 内
    ok = ok and jitter_point(100, 200, 0) == (100, 200)
    for _ in range(50):
        jx, jy = jitter_point(500, 300, 20)
        ok = ok and 480 <= jx <= 520 and 280 <= jy <= 320

    # 点击范围解析：空/非法回退 0；负数归零；上限 2000
    ok = ok and parse_pixels("") == 0 and parse_pixels("abc") == 0
    ok = ok and parse_pixels("-8") == 0 and parse_pixels("99999") == 2000 \
        and parse_pixels("15") == 15

    # 自动清理间隔解析：空/非法回退 10；下限 1 上限 1440 分钟
    ok = ok and parse_minutes("") == 10 and parse_minutes("abc") == 10
    ok = ok and parse_minutes("0") == 1 and parse_minutes("99999") == 1440 \
        and parse_minutes("5") == 5

    # ---- 结算重放：指令长度估算（覆盖跳回边界的关键路径）----
    ok = ok and instr_len32(b"\x53") == 1                          # push ebx
    ok = ok and instr_len32(bytes.fromhex("8B4508")) == 3          # mov eax,[ebp+8]
    ok = ok and instr_len32(bytes.fromhex("81EC40010000")) == 6    # sub esp,140h
    ok = ok and instr_len32(bytes.fromhex("894DFC")) == 3          # mov [ebp-4],ecx
    ok = ok and instr_len32(bytes.fromhex("8B855C010000")) == 6    # mov eax,[ebp+15Ch]
    ok = ok and instr_len32(bytes.fromhex("8B04BD78563412")) == 7  # mov eax,[sib+disp32]
    ok = ok and instr_len32(bytes.fromhex("B878563412")) == 5      # mov eax,imm32
    ok = ok and instr_len32(bytes.fromhex("6810270000")) == 5      # push 2710h
    ok = ok and instr_len32(bytes.fromhex("83C408")) == 3          # add esp,8
    ok = ok and instr_len32(bytes.fromhex("F00FC11578563412")) == 8  # lock xadd [mem],edx
    ok = ok and instr_len32(bytes.fromhex("0F8F78563412")) is None  # jg rel32 拒绝
    ok = ok and instr_len32(bytes.fromhex("E800000000")) == 5      # call rel32 允许（重定位）
    ok = ok and instr_len32(bytes.fromhex("E900000000")) == 5      # jmp rel32 允许（重定位）
    ok = ok and instr_len32(bytes.fromhex("EB00")) is None          # jmp short 拒绝
    ok = ok and instr_len32(b"\xC3") is None                        # ret 拒绝

    # 抓包入口搬移判定：整条指令边界 + E8/E9 重定位表
    st = hook_stolen(bytes.fromhex("558BEC5153") + b"\x90" * 11, 0x40000000)
    ok = ok and st[0] == bytes.fromhex("558BEC5153") and st[1] == ()
    st = hook_stolen(bytes.fromhex("558BEC518B450C8945FC") + b"\x00" * 8, 0x40000000)
    ok = ok and st[0] == bytes.fromhex("558BEC518B450C") and st[1] == ()  # 战斗A 真实序言
    st = hook_stolen(bytes.fromhex("E927C84401") + b"\x90" * 11, 0x40000000 + 0x63C950)
    ok = ok and st[0] == b"\xE9\x27\xC8\x44\x01" and st[1] == \
        ((0, 0x40000000 + 0x63C950 + 5 + 0x0144C827),)              # E9 thunk 入口
    ok = ok and hook_stolen(bytes.fromhex("558BEC51C3") + b"\x90" * 11, 0) is None
    ok = ok and hook_stolen(bytes.fromhex("558BEC51EB05") + b"\x90" * 10, 0) is None
    ok = ok and hook_stolen(bytes.fromhex("558BEC51"), 0) is None   # 字节不足

    # 钩子代码：结构 + 跳回边界校验（战斗A：len=a3 buf=a2）
    send_addr = 0x40000000 + 0x63FBB0
    stolen = bytes.fromhex("558BEC518B450C")
    hcode = hook_code(0x10000000, 0x10001000, send_addr, stolen, (), 3, 2)
    ok = ok and len(hcode) <= 4096 and hcode[0] == 0x9C and hcode[1] == 0x60
    ok = ok and b"\xF0\x0F\xC1\x35" + struct.pack("<I", 0x10001000) in hcode
    ok = ok and struct.pack("<I", 0x10001000 + HOOK_MARKER_OFF) in hcode
    ok = ok and struct.pack("<I", 0x10001000 + HOOK_SLOTS_OFF) in hcode
    ok = ok and hcode[len(hcode) - len(stolen) - 5:len(hcode) - 5] == stolen
    ok = ok and hcode[len(hcode) - len(stolen) - 7:len(hcode) - len(stolen) - 5] == b"\x61\x9D"
    # 恢复必须 popad→popfd（压栈 9C,60 的逆序）：反序会把 EDI 弹进 EFLAGS、把 EFLAGS 装进 ESP
    ok = ok and hcode[-5] == 0xE9
    rel = struct.unpack_from("<I", hcode, len(hcode) - 4)[0]
    ok = ok and 0x10000000 + len(hcode) + rel == send_addr + len(stolen)
    # E9 thunk 重定位：stolen 里的 E9 改跳到原目标
    thunk = 0x40000000 + 0x63C950
    st2 = hook_stolen(bytes.fromhex("E927C84401") + b"\x90" * 11, thunk)
    hcode2 = hook_code(0x10000000, 0x10001000, thunk, st2[0], st2[1], 4, 3)
    p_stolen = len(hcode2) - len(st2[0]) - 5
    rel2 = struct.unpack_from("<i", hcode2, p_stolen + 1)[0]
    ok = ok and 0x10000000 + p_stolen + 5 + rel2 == st2[1][0][1]

    # 重放代码：参数压栈顺序（cdecl 从右往左）、状态写回、marker 可选
    payload = bytes(range(10))
    pushes = replay_pushes(KILL_SEND_OFF, 8121, payload)
    ok = ok and pushes == (0, 0, 10, "BUF", 8121)
    scode = send_packet_code(0x20000000, 0x20001000, 0x40000000 + 0x63FBB0, pushes,
                             0x20001000 + HOOK_MARKER_OFF)
    ok = ok and len(scode) <= 4096 and scode.rfind(b"\xC2\x04\x00") != -1 \
        and scode.rfind(b"\xC3") > scode.rfind(b"\xC2\x04\x00")   # 末尾是 SEH 处理器的 ret
    ok = ok and b"\x68" + struct.pack("<I", 8121) in scode
    ok = ok and b"\x68" + struct.pack("<I", 0x20001000) in scode
    ok = ok and b"\x68" + struct.pack("<I", len(payload)) in scode
    ok = ok and b"\x83\xC4\x14" in scode                          # add esp,0x14（5 参）
    ok = ok and struct.pack("<I", 0x40000000 + 0x63FBB0) in scode
    ok = ok and struct.pack("<I", 0x20001000 + HOOK_MARKER_OFF) in scode
    ok = ok and struct.pack("<I", 0x20001000 + 128) in scode
    plain = send_packet_code(0x20000000, 0x20001000, 0x40000000,
                             replay_pushes(KILL_SEND_OFF, 8121, payload), 0)
    ok = ok and struct.pack("<I", 0x20001000 + HOOK_MARKER_OFF) not in plain
    # 大厅A/B 参数表
    ok = ok and replay_pushes(MAIN_A_OFF, 6053, b"xyz", 0, 0x1234, 19) == (3, "BUF", 0, 6053)
    ok = ok and replay_pushes(MAIN_B_OFF, 6001, b"") == (0, 6001)
    ok = ok and replay_pushes(MAIN_B_OFF, 6001, b"q") == ("BUF", 6001)

    # recv 下行钩子：序言白名单（delta = stolen 对 esp 的净变化，解码至 ≥5 字节止）
    ok = ok and recv_prologue_delta(b"\x8B\xFF\x55\x8B\xEC\x81\xEC\xC0\x00\x00\x00") == -4
    ok = ok and recv_prologue_delta(b"\x8B\xFF\x55\x8B\xEC") == -4
    ok = ok and recv_prologue_delta(b"\x55\x8B\xEC\x83\xEC\x48") == -76
    ok = ok and recv_prologue_delta(b"\x53\x56\x57\x55\x8B\xEC") == -16
    ok = ok and recv_prologue_delta(b"\x8B\xFF") is None               # 不足 5 字节
    ok = ok and recv_prologue_delta(b"\xE8\x00\x00\x00\x00\x90") is None   # call 拒绝
    ok = ok and recv_prologue_delta(b"\x54\x55\x56\x57\x8B\xEC") is None   # push esp 拒绝
    ok = ok and recv_prologue_delta(b"\x6A\x01\x55\x8B\xEC") == -8      # push imm8
    ok = ok and recv_prologue_delta(b"\x68\x01\x02\x03\x04") == -4      # push imm32
    rcode = recv_hook_code(0x30000000, 0x30001000, 0x71000005,
                           b"\x8B\xFF\x55\x8B\xEC", -4)
    ok = ok and b"\xB8" + struct.pack("<I", 0x71000005) in rcode       # call recv+5
    ok = ok and struct.pack("<I", 0x30001000 + HOOK_CTR_OFF) in rcode
    ok = ok and struct.pack("<I", 0x30001000 + HOOK_SLOTS_OFF) in rcode
    ok = ok and b"\x8B\x74\x24\x2C" in rcode                           # mov esi,[esp+44]=buf
    ok = ok and rcode[-3:] == b"\xC2\x10\x00"                          # ret 16
    tcode = recv_hook_code(0x30000000, 0x30001000, 0x71000000, b"", 0)  # E9 thunk 变体
    ok = ok and tcode[0] == 0x60 and b"\xB8" + struct.pack("<I", 0x71000000) in tcode \
        and tcode[-3:] == b"\xC2\x10\x00"
    module_base_named(0, "ws2_32.dll")   # 任意结果皆可：路径不崩、诊断有值（wine 会命中自身）

    # hex 工具与过滤、槽解析
    ok = ok and parse_hex("55 8b ec") == b"\x55\x8b\xec"
    ok = ok and parse_hex("55,8B\nEC") == bytes([0x55, 0x8B, 0xEC])
    ok = ok and parse_hex("5") is None and parse_hex("GG") is None and parse_hex("") is None
    body = bytes(range(20))
    ok = ok and patch_hex(body, bytes([3, 4]), bytes([9, 9])) == body[:3] + b"\x09\x09" + body[5:]
    ok = ok and patch_hex(body, b"\xFF", b"\x01") == body
    ok = ok and patch_hex(body, b"", b"\x01") is None
    ok = ok and parse_filter_ids("8121, 0x1FB9 abc") == {8121}      # 0x1FB9=8121 去重
    ok = ok and parse_filter_ids("21900 08121") == {21900, 8121}    # 前导零按十进制
    slot = bytearray(HOOK_SLOT_SIZE)
    struct.pack_into("<6I", slot, 0, 8121, 3, 0, 7, 9, 1)
    slot[HOOK_SLOT_HDR:HOOK_SLOT_HDR + 3] = b"\xAA\xBB\xCC"
    parsed = parse_capture_slot(bytes(slot))
    ok = ok and parsed["id"] == 8121 and parsed["mine"] and parsed["data"] == b"\xAA\xBB\xCC" \
        and parsed["a3"] == 7 and parsed["a4"] == 9
    empty = parse_capture_slot(bytes(HOOK_SLOT_SIZE))
    ok = ok and empty["data"] == b"" and not empty["mine"]
    ok = ok and packet_line(3, {"time": "12:00:00", "id": 8121, "mine": True,
                                "fn": KILL_SEND_OFF,
                                "data": b"\x55\x8B\xEC"}).startswith("#3")

    # PE 节表解析（导出代码段用）：合成 2 节头块
    def sec(name, vsize, va, chars):
        return name.ljust(8).encode("latin1") + struct.pack("<II", vsize, va) + \
            b"\x00" * 20 + struct.pack("<I", chars)
    hdr = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, 2, 0, 0, 0, 0xE0, 0x22) + \
        b"\x00" * 0xE0 + sec(".text", 0x1000, 0x1000, 0x60000020) + \
        sec(".rdata", 0x2000, 0x2000, 0x40000040)
    parsed_secs = pe_sections(hdr)
    ok = ok and len(parsed_secs) == 2 and parsed_secs[0][0] == ".text" \
        and parsed_secs[0][2] == 0x1000 and parsed_secs[0][3] == 0x60000020 \
        and parsed_secs[1][1] == 0x2000
    ok = ok and pe_sections(b"MZ\x00\x00") == [] and pe_sections(b"") == []

    # 毫秒解析（自动点击/重放循环间隔）：与秒制的 parse_delay_ms 区分
    ok = ok and parse_ms("500", 500) == 500 and parse_ms("", 500) == 500
    ok = ok and parse_ms("0", 500) == 0 and parse_ms("-3", 500) == 0
    ok = ok and parse_ms("abc", 500) == 500 and parse_ms("99999999", 500) == 3600000

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


def is_admin():
    """当前进程是否以管理员身份运行；非 Windows 或查询失败返回 False。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


def elevate():
    """以管理员身份重启当前进程（触发 UAC）。成功返回 True，用户取消/失败返回 False。"""
    import sys
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = " ".join('"%s"' % a for a in sys.argv[1:])
    else:
        exe = sys.executable
        params = '"%s" %s' % (sys.argv[0],
                              " ".join('"%s"' % a for a in sys.argv[1:]))
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return result > 32
    except OSError:
        return False


def run_ui():
    import tkinter as tk
    from tkinter import ttk

    class App:
        def __init__(self, root):
            self.root = root
            root.title("属性助手 · 单机版 v1030i（下行抓包）")
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
            ttk.Button(top, text="清理游戏内存", command=self.clean_memory).grid(row=0, column=3,
                                                                                 padx=(8, 0))
            ttk.Button(top, text="以管理员重启", command=self.elevate_self).grid(
                row=0, column=4, padx=(8, 0))

            memframe = ttk.Frame(root)
            memframe.pack(fill="x", padx=12, pady=(0, 2))
            self.mem_auto = tk.BooleanVar(value=False)
            self.mem_every = tk.StringVar(value="10")
            self.mem_last_clean = 0
            ttk.Checkbutton(memframe, text="定时清理游戏工作集，每",
                            variable=self.mem_auto,
                            command=self.on_mem_toggle).pack(side="left")
            ttk.Entry(memframe, textvariable=self.mem_every, width=4).pack(side="left")
            ttk.Label(memframe, text="分钟（治标：把内存页换出；泄漏块本身无法外部回收）").pack(
                side="left", padx=(4, 8))
            self.mem_status = tk.StringVar(
                value="清理后游戏首次访问被换出页面时可能短暂卡顿，属正常现象。")
            ttk.Label(memframe, textvariable=self.mem_status).pack(side="left")

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
            self.kill_last_fire = 0
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

            movebox = ttk.LabelFrame(root, text="自动跑图（后台按键模拟，不写内存）")
            movebox.pack(fill="x", padx=12, pady=(0, 4))
            self.move_var = tk.BooleanVar(value=False)
            self.move_key = tk.StringVar(value="右(D)")
            self.move_hold = tk.StringVar(value="2")
            self.move_release = tk.StringVar(value="0.5")
            self.move_pressed = False
            self.move_phase_at = 0
            self.move_hwnd = 0
            self.pid = 0
            ttk.Checkbutton(movebox, text="自动跑图（检测到角色后移动）",
                            variable=self.move_var,
                            command=self.on_move_toggle).grid(row=0, column=0,
                                                              sticky="w", padx=8,
                                                              pady=4)
            ttk.Label(movebox, text="方向：").grid(row=0, column=1, sticky="e", pady=4)
            ttk.OptionMenu(movebox, self.move_key, self.move_key.get(),
                           *MOVE_KEYS).grid(row=0, column=2, sticky="w", pady=4)
            ttk.Label(movebox, text="按住(秒)：").grid(row=0, column=3, sticky="e",
                                                       pady=4)
            ttk.Entry(movebox, textvariable=self.move_hold, width=6).grid(
                row=0, column=4, sticky="w", pady=4)
            ttk.Label(movebox, text="松开(秒)：").grid(row=0, column=5, sticky="e",
                                                       pady=4)
            ttk.Entry(movebox, textvariable=self.move_release, width=6).grid(
                row=0, column=6, sticky="w", pady=4)
            self.move_status = tk.StringVar(
                value="按住 0 = 一直按住不松；松开 0 = 到点立刻再按。取消勾选立即松键。")
            ttk.Label(movebox, textvariable=self.move_status, wraplength=520,
                      justify="left").grid(row=1, column=0, columnspan=7, sticky="w",
                                           padx=8, pady=(0, 6))

            clickbox = ttk.LabelFrame(root, text="自动点击（前台模拟鼠标，不写内存）")
            clickbox.pack(fill="x", padx=12, pady=(0, 4))
            self.click_var = tk.BooleanVar(value=False)
            self.click_interval = tk.StringVar(value="500")
            self.click_radius = tk.StringVar(value="0")
            self.click_button = tk.StringVar(value="左键")
            self.click_x = -1
            self.click_y = -1
            self.click_last = 0
            self.click_count = 0
            self.click_hwnd = 0
            self.pick_after_id = 0
            self.pid = 0
            ttk.Checkbutton(clickbox, text="自动点击",
                            variable=self.click_var,
                            command=self.on_click_toggle).grid(
                row=0, column=0, sticky="w", padx=8, pady=4)
            ttk.Button(clickbox, text="拾取位置(3秒)",
                       command=self.pick_position).grid(row=0, column=1,
                                                        sticky="w", pady=4)
            ttk.Label(clickbox, text="间隔(毫秒)：").grid(row=0, column=2,
                                                         sticky="e", pady=4)
            ttk.Entry(clickbox, textvariable=self.click_interval, width=7).grid(
                row=0, column=3, sticky="w", pady=4)
            ttk.Label(clickbox, text="范围(像素)：").grid(row=0, column=4,
                                                         sticky="e", pady=4)
            ttk.Entry(clickbox, textvariable=self.click_radius, width=6).grid(
                row=0, column=5, sticky="w", pady=4)
            ttk.OptionMenu(clickbox, self.click_button, self.click_button.get(),
                           "左键", "右键").grid(row=0, column=6, sticky="w",
                                               pady=4)
            self.click_status = tk.StringVar(
                value="点「拾取位置」后 3 秒内把鼠标移到游戏目标处；范围 >0 时在拾取点附近随机取点。")
            ttk.Label(clickbox, textvariable=self.click_status, wraplength=520,
                      justify="left").grid(row=1, column=0, columnspan=7,
                                           sticky="w", padx=8, pady=(0, 6))

            replaybox = ttk.LabelFrame(root, text="结算重放（抓包 → 改字节 → 原生重发；风险自负）")
            replaybox.pack(fill="x", padx=12, pady=(0, 4))
            self.capture_var = tk.BooleanVar(value=False)
            self.capture_filter = tk.StringVar(value="")
            self.capture_hooks = []      # 已安装钩子 [(rva, name, block, orig, replay_addr)]
            self.capture_seen = {}       # rva → 已读发包计数
            self.recv_hook = None        # recv 下行钩子 [addr, name, block, orig]
            self.recv_seen = 0
            self.recv_hook_err = ""
            self.send_hook_err = {}      # 上行 send 钩失败原因（name → 原因）
            self.edit_fn = KILL_SEND_OFF     # 编辑区当前包的来源函数与原始参数
            self.edit_a2 = 0
            self.edit_a3 = 0
            self.edit_a4 = 0
            self.packets = []
            self.view = []               # 列表当前显示（过滤后）的记录
            self.send_job = PacketJob()
            self.loop_var = tk.BooleanVar(value=False)
            self.loop_interval = tk.StringVar(value="1000")
            self.loop_count = tk.StringVar(value="0")
            self.loop_left = 0
            self.loop_last = 0
            self.replay_sent = 0
            self.batch_queue = []        # 连发序列待发记录
            self.batch_total = 0
            self.settle_extras_var = tk.BooleanVar(value=False)  # 一键结算是否附带确认包
            crow = ttk.Frame(replaybox)
            crow.pack(fill="x", padx=8, pady=(4, 2))
            ttk.Checkbutton(crow, text="开启抓包", variable=self.capture_var,
                            command=self.on_capture_toggle).pack(side="left")
            ttk.Label(crow, text="只显示ID:").pack(side="left", padx=(10, 2))
            ttk.Entry(crow, textvariable=self.capture_filter, width=11).pack(side="left")
            ttk.Button(crow, text="清空记录",
                       command=self.clear_packets).pack(side="left", padx=(10, 0))
            ttk.Button(crow, text="保存记录",
                       command=self.save_packets).pack(side="left", padx=(4, 0))
            ttk.Button(crow, text="载入记录",
                       command=self.load_packets).pack(side="left", padx=(4, 0))
            ttk.Button(crow, text="导出代码段",
                       command=self.dump_code_sections).pack(side="left", padx=(4, 0))
            lrow = ttk.Frame(replaybox)
            lrow.pack(fill="x", padx=8, pady=2)
            self.packet_list = tk.Listbox(lrow, height=6, width=92, font="TkFixedFont")
            pscroll = ttk.Scrollbar(lrow, command=self.packet_list.yview)
            self.packet_list.configure(yscrollcommand=pscroll.set)
            self.packet_list.pack(side="left")
            pscroll.pack(side="left", fill="y")
            erow = ttk.Frame(replaybox)
            erow.pack(fill="x", padx=8, pady=2)
            ttk.Button(erow, text="选中→编辑",
                       command=self.load_selected_packet).pack(side="left")
            ttk.Label(erow, text="ID:").pack(side="left", padx=(10, 2))
            self.replay_id = tk.StringVar(value="8121")
            ttk.Entry(erow, textvariable=self.replay_id, width=8).pack(side="left")
            ttk.Label(erow, text="查找(hex):").pack(side="left", padx=(10, 2))
            self.hex_find = tk.StringVar(value="")
            ttk.Entry(erow, textvariable=self.hex_find, width=13).pack(side="left")
            ttk.Label(erow, text="替换为:").pack(side="left", padx=(6, 2))
            self.hex_replace = tk.StringVar(value="")
            ttk.Entry(erow, textvariable=self.hex_replace, width=13).pack(side="left")
            ttk.Button(erow, text="应用替换",
                       command=self.apply_hex_patch).pack(side="left", padx=(8, 0))
            ttk.Button(erow, text="取本局token",
                       command=self.apply_local_token).pack(side="left", padx=(8, 0))
            self.hex_box = tk.Text(replaybox, height=4, wrap="char", font="TkFixedFont")
            self.hex_box.pack(fill="x", padx=8, pady=2)
            srow = ttk.Frame(replaybox)
            srow.pack(fill="x", padx=8, pady=(0, 2))
            ttk.Button(srow, text="发送一次", command=self.send_once).pack(side="left")
            ttk.Button(srow, text="连发序列",
                       command=self.send_batch).pack(side="left", padx=(8, 0))
            ttk.Button(srow, text="一键结算",
                       command=self.one_key_settle).pack(side="left", padx=(8, 0))
            ttk.Button(srow, text="一键胜利",
                       command=self.one_key_win).pack(side="left", padx=(8, 0))
            ttk.Checkbutton(srow, text="带确认包", variable=self.settle_extras_var
                            ).pack(side="left", padx=(10, 0))
            ttk.Checkbutton(srow, text="循环", variable=self.loop_var,
                            command=self.on_loop_toggle).pack(side="left", padx=(10, 0))
            ttk.Label(srow, text="间隔(ms):").pack(side="left", padx=(8, 2))
            ttk.Entry(srow, textvariable=self.loop_interval, width=7).pack(side="left")
            ttk.Label(srow, text="次数(0=无限):").pack(side="left", padx=(8, 2))
            ttk.Entry(srow, textvariable=self.loop_count, width=6).pack(side="left")
            self.replay_status = tk.StringVar(
                value="先开抓包完整打一局真实结算；在列表选中结算包载入编辑区，改字节后重放。")
            ttk.Label(replaybox, textvariable=self.replay_status, wraplength=620,
                      justify="left").pack(fill="x", padx=8, pady=(0, 6))
            self.capture_filter.trace_add("write", lambda *_: self.refresh_packet_list())

            self.status = tk.StringVar(
                value="游戏运行后选择进程点击“启动”；换局自动继续，取消勾选会恢复原值。")
            ttk.Label(root, textvariable=self.status, wraplength=520,
                      justify="left").pack(fill="x", padx=12, pady=(4, 12))

            self.load_settings()
            self.refresh()
            if not is_admin():
                self.status.set("当前非管理员权限；若游戏以管理员运行，启动会提示拒绝访问，"
                                "可点右上角「以管理员重启」。")
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
            self.move_var.set(bool(data.get("move", False)))
            self.move_key.set(str(data.get("move_key", "右(D)")))
            self.move_hold.set(str(data.get("move_hold", "2")))
            self.move_release.set(str(data.get("move_release", "0.5")))
            self.click_var.set(bool(data.get("click", False)))
            self.click_interval.set(str(data.get("click_interval", "500")))
            self.click_radius.set(str(data.get("click_radius", "0")))
            self.click_button.set(str(data.get("click_button", "左键")))
            self.click_x = int(data.get("click_x", -1))
            self.click_y = int(data.get("click_y", -1))
            self.click_last = 0  # 恢复勾选后重新计时，避免启动即点
            self.mem_auto.set(bool(data.get("mem_auto", False)))
            self.mem_every.set(str(data.get("mem_every", "10")))
            self.mem_last_clean = now_ms()  # 恢复勾选后重新计时，避免启动即清
            self.capture_var.set(bool(data.get("capture", False)))
            self.capture_filter.set(str(data.get("capture_filter", "")))
            self.loop_interval.set(str(data.get("loop_interval", "1000")))
            self.loop_count.set(str(data.get("loop_count", "0")))
            self.replay_id.set(str(data.get("replay_id", "8121")))

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
                    "suicide_delay": self.suicide_delay.get(),
                    "move": self.move_var.get(),
                    "move_key": self.move_key.get(),
                    "move_hold": self.move_hold.get(),
                    "move_release": self.move_release.get(),
                    "click": self.click_var.get(),
                    "click_interval": self.click_interval.get(),
                    "click_radius": self.click_radius.get(),
                    "click_button": self.click_button.get(),
                    "click_x": self.click_x,
                    "click_y": self.click_y,
                    "mem_auto": self.mem_auto.get(),
                    "mem_every": self.mem_every.get(),
                    "capture": self.capture_var.get(),
                    "capture_filter": self.capture_filter.get(),
                    "loop_interval": self.loop_interval.get(),
                    "loop_count": self.loop_count.get(),
                    "replay_id": self.replay_id.get()}
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
                    self.status.set("无法打开进程（拒绝访问）。游戏大概率以管理员运行；"
                                    "点右上角「以管理员重启」或右键本程序以管理员运行。")
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
            self.pid = pid
            self.auto_fault = False
            # 基址自检：立刻试读两个全局指针，判断偏移是否仍有效
            def ptr_str(v):
                return "不可读✗" if v is None else ("0（空）" if v == 0 else "0x%08X ✓" % v)
            mgr = read_u32(handle, base + MANAGER_PTR)
            inf = read_u32(handle, base + INFO_PTR)
            probe = "自检：管理器=%s 信息=%s" % (ptr_str(mgr), ptr_str(inf))
            self.status.set(f"已启动{note}（基址 0x{base:08X}，模块查找："
                            f"{MODULE_LOOKUP_INFO or '未知'}；{probe}）。"
                            "沿用勾选设置，换局自动继续，无需重复连接。")

        def stop_clicked(self):
            self.stop()

        def stop(self, silent=False):
            if not self.handle:
                if not silent:
                    self.status.set("尚未连接游戏进程。")
                return True
            self.kill_cancel = True
            self.stop_capture()
            if self.kill_busy() or self.send_job.busy():
                # 不强杀线程：等当前原生调用返回后再断开（kill.h 同款语义）
                self.disconnect_pending = True
                if not silent:
                    self.status.set("等待自动调用结束后断开；勾选已保留。")
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
                elif self.disconnect_pending and not self.kill_busy() \
                        and not self.send_job.busy():
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
                    return  # 调用进行中，下一轮再查；超时由 poll 内部强杀回收
                target = self.current_target
                if target and result == 1:
                    self.kill_done += 1
                else:
                    self.kill_skipped += 1
                    if result == 2:
                        self.round_reasons["预检跳过"] = self.round_reasons.get("预检跳过", 0) + 1
                    elif result == 4:
                        self.round_reasons["原生拒绝"] = self.round_reasons.get("原生拒绝", 0) + 1
                    elif result == -3:
                        self.round_reasons["调用超时"] = self.round_reasons.get("调用超时", 0) + 1
                        self.kill_cancel = True
                        self.auto_fault = True
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
                interval = parse_delay_ms(self.kill_delay.get())
                if interval and now_ms() - self.kill_last_fire < interval:
                    self.kill_next -= 1  # 击杀间隔未到：目标退回队头，下轮再试
                    return
                if not self.kill_job.start(self.handle, k):
                    self.kill_cancel = True
                    self.auto_fault = True
                    self.kill_skipped += 1
                    break
                self.kill_last_fire = now_ms()
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

        def on_move_toggle(self):
            # 取消勾选立即松键（move_tick 也会兜底松键，这里保证即时响应）
            if not self.move_var.get() and self.move_pressed:
                send_move_key(self.move_hwnd,
                              MOVE_KEYS.get(self.move_key.get(), 0x44), False)
                self.move_pressed = False
                self.move_phase_at = 0
            self.save_settings()

        def move_tick(self):
            """自动跑图状态机：检测到角色、游戏前台才按键；取消/失联/换局立即松键。"""
            want = self.move_var.get() and self.handle and bool(self.actor)
            now = now_ms()
            vk = MOVE_KEYS.get(self.move_key.get(), 0x44)
            if not want:
                if self.move_pressed:
                    send_move_key(self.move_hwnd, vk, False)
                    self.move_pressed = False
                    self.move_phase_at = 0
                if self.move_var.get() and self.handle:
                    self.move_status.set("已勾选；检测到角色（进战斗）后开始。")
                return
            if not self.move_hwnd or not user32().IsWindow(self.move_hwnd):
                self.move_hwnd = find_main_window(self.pid)
                if not self.move_hwnd:
                    self.move_status.set("未找到游戏窗口，无法发送按键。")
                    return
            if not game_foreground(self.pid):
                # SendInput 作用于前台窗口：游戏不在前台时不投递，避免按键打进别的程序
                if self.move_pressed:
                    send_move_key(self.move_hwnd, vk, False)
                    self.move_pressed = False
                    self.move_phase_at = now_ms()
                self.move_status.set("游戏窗口不在前台，跑图已暂停；切回游戏窗口即自动恢复。")
                return
            hold = parse_delay_ms(self.move_hold.get())
            release = parse_delay_ms(self.move_release.get(), 500)
            if self.move_pressed:
                if hold and now - self.move_phase_at >= hold:
                    send_move_key(self.move_hwnd, vk, False)
                    self.move_pressed = False
                    self.move_phase_at = now
            elif not release or now - self.move_phase_at >= release:
                send_move_key(self.move_hwnd, vk, True)
                self.move_pressed = True
                self.move_phase_at = now

        def on_click_toggle(self):
            # 勾选即重新计时，避免上次残留时间点导致启动立即点击
            self.click_last = now_ms()
            self.save_settings()

        def pick_position(self):
            """3 秒后抓取当前鼠标位置作为点击点；期间把鼠标移到游戏目标处即可。"""
            if self.pick_after_id:
                self.root.after_cancel(self.pick_after_id)
            self.click_status.set("3 秒后拾取鼠标当前位置，请立即把鼠标移到游戏目标点…")
            self.pick_after_id = self.root.after(3000, self.grab_cursor)

        def grab_cursor(self):
            self.pick_after_id = 0
            pt = wintypes.POINT()
            if not user32().GetCursorPos(ctypes.byref(pt)):
                self.click_status.set("拾取失败（错误码 %d），请重试。" % ctypes.get_last_error())
                return
            self.click_x, self.click_y = pt.x, pt.y
            self.click_last = now_ms()
            self.click_status.set("已拾取 (%d, %d)；勾选自动点击后按间隔在此处点击。" % (pt.x, pt.y))
            self.save_settings()

        def click_tick(self):
            """自动点击：仅游戏前台时投递；未拾取坐标/失联即暂停，不做任何注入。"""
            if not self.click_var.get():
                return
            if self.click_x < 0 or self.click_y < 0:
                self.click_status.set("已勾选；先点「拾取位置」选择点击点。")
                return
            if not self.handle:
                self.click_status.set("未连接游戏，自动点击暂停。")
                return
            if not self.click_hwnd or not user32().IsWindow(self.click_hwnd):
                self.click_hwnd = find_main_window(self.pid)
                if not self.click_hwnd:
                    self.click_status.set("未找到游戏窗口，自动点击暂停。")
                    return
            if not game_foreground(self.pid):
                # SendInput 作用于前台窗口：游戏不在前台时不投递，避免点击打进别的程序
                self.click_status.set("游戏窗口不在前台，自动点击已暂停；切回游戏窗口即自动恢复。")
                return
            now = now_ms()
            interval = parse_ms(self.click_interval.get(), 500)
            if not interval:
                interval = 500  # 0/非法回退 500ms，避免死循环式狂点
            if now - self.click_last < interval:
                return
            self.click_last = now
            radius = parse_pixels(self.click_radius.get())
            x, y = jitter_point(self.click_x, self.click_y, radius)
            if send_mouse_click(x, y, self.click_button.get()):
                self.click_count += 1
                self.click_status.set("点击中：(点 %d, %d)%s 已点击 %d 次。" % (
                    x, y, "（范围 %d 随机）" % radius if radius else "", self.click_count))
            else:
                self.click_status.set("点击注入失败（错误码 %d）。" % ctypes.get_last_error())

        # -- 结算重放：抓包 + 改字节 + 原生重发 --
        def on_capture_toggle(self):
            if self.capture_var.get() and not self.handle:
                self.replay_status.set("已勾选抓包；连接游戏进程后自动安装钩子。")
            self.save_settings()

        def on_loop_toggle(self):
            if self.loop_var.get():
                count = parse_ms(self.loop_count.get(), 0)
                self.loop_left = -1 if count == 0 else count  # -1 = 无限
                self.loop_last = 0
                self.replay_sent = 0
                self.replay_status.set("循环重放已就绪；发送失败或异常会自动停止。")
            self.save_settings()

        def _install_hook(self, rva, name, len_arg, buf_arg):
            """单函数入口写 E9 跳板；失败返回 None（原因记入 self.send_hook_err，不阻断其他函数）。"""
            send_addr = self.base + rva
            raw = read_mem(self.handle, send_addr, HOOK_READ_BYTES)
            parsed = hook_stolen(raw, send_addr) if raw else None
            if not parsed:
                self.send_hook_err[name] = ("入口不可读" if not raw
                                            else "序言不可搬移:%s" % bytes(raw[:12]).hex(" "))
                return None
            stolen, relocs = parsed
            block = k32.VirtualAllocEx(self.handle, None, 0x12000, MEM_COMMIT_RESERVE,
                                       PAGE_READWRITE) or 0
            if not block:
                self.send_hook_err[name] = "VirtualAllocEx 失败(err=%d)" % ctypes.get_last_error()
                return None
            code = hook_code(block, block + 0x1000, send_addr, stolen, relocs,
                             len_arg, buf_arg)
            got = ctypes.c_size_t(0)
            ok = bool(k32.WriteProcessMemory(self.handle, ctypes.c_void_p(block), code,
                                             len(code), ctypes.byref(got))) \
                and got.value == len(code)
            if ok:
                previous = wintypes.DWORD(0)
                ok = bool(k32.VirtualProtectEx(self.handle, ctypes.c_void_p(block), 4096,
                                               PAGE_EXECUTE_READ, ctypes.byref(previous)))
                k32.FlushInstructionCache(self.handle, ctypes.c_void_p(block), len(code))
            if ok:
                jump = b"\xE9" + struct.pack("<I", (block - (send_addr + 5)) & 0xFFFFFFFF)
                ok = bool(k32.WriteProcessMemory(self.handle, ctypes.c_void_p(send_addr),
                                                 jump, 5, ctypes.byref(got))) and got.value == 5
                k32.FlushInstructionCache(self.handle, ctypes.c_void_p(send_addr), 5)
            if not ok:
                k32.VirtualFreeEx(self.handle, ctypes.c_void_p(block), 0, MEM_RELEASE)
                self.send_hook_err[name] = "写内存/改保护失败(err=%d)" % ctypes.get_last_error()
                return None
            replay_addr = send_addr
            if stolen[:1] == b"\xE9" and relocs:
                replay_addr = relocs[0][1]   # E9 thunk 真身地址（记录备用，重放现统一走入口）
            return [rva, name, block, stolen, replay_addr]

        def _install_recv_hook(self):
            """钩 ws2_32.recv 抓服务器下行；失败原因写入 recv_hook_err（不阻断）。"""
            self.recv_hook_err = ""
            wbase = module_base_named(self.pid, "ws2_32.dll", self.handle)
            if not wbase:
                self.recv_hook_err = "ws2_32.dll 未找到（%s）" % MODULE_LOOKUP_INFO
                return None
            rva = resolve_export(self.handle, wbase, "recv")
            if not rva:
                self.recv_hook_err = "recv 导出解析失败（ws2_32@%08X）" % wbase
                return None
            recv_addr = wbase + rva
            raw = read_mem(self.handle, recv_addr, HOOK_READ_BYTES)
            parsed = hook_stolen(raw, recv_addr) if raw else None
            if not parsed:
                self.recv_hook_err = "入口不可搬移：%s" % (raw or b"").hex(" ")
                return None
            stolen, relocs = parsed
            if len(relocs) == 1 and relocs[0][0] == 0 and len(stolen) == 5 \
                    and stolen[0] == 0xE9:
                body, st, esp_delta = relocs[0][1], b"", 0     # 入口=E9 thunk → 直调真身
            elif relocs:
                self.recv_hook_err = "入口含 E8/E9：%s" % raw.hex(" ")
                return None
            else:
                esp_delta = recv_prologue_delta(stolen)
                if esp_delta is None:
                    self.recv_hook_err = "序言非白名单：%s" % stolen.hex(" ")
                    return None
                body, st = recv_addr + len(stolen), stolen
            block = k32.VirtualAllocEx(self.handle, None, 0x12000, MEM_COMMIT_RESERVE,
                                       PAGE_READWRITE) or 0
            if not block:
                self.recv_hook_err = "远程内存分配失败"
                return None
            code = recv_hook_code(block, block + 0x1000, body, st, esp_delta)
            got = ctypes.c_size_t(0)
            ok = bool(k32.WriteProcessMemory(self.handle, ctypes.c_void_p(block), code,
                                             len(code), ctypes.byref(got))) \
                and got.value == len(code)
            if ok:
                previous = wintypes.DWORD(0)
                ok = bool(k32.VirtualProtectEx(self.handle, ctypes.c_void_p(block), 4096,
                                               PAGE_EXECUTE_READ, ctypes.byref(previous)))
                k32.FlushInstructionCache(self.handle, ctypes.c_void_p(block), len(code))
            if ok:
                jump = b"\xE9" + struct.pack("<I", (block - (recv_addr + 5)) & 0xFFFFFFFF)
                ok = bool(k32.WriteProcessMemory(self.handle, ctypes.c_void_p(recv_addr),
                                                 jump, 5, ctypes.byref(got))) and got.value == 5
                k32.FlushInstructionCache(self.handle, ctypes.c_void_p(recv_addr), 5)
            if not ok:
                k32.VirtualFreeEx(self.handle, ctypes.c_void_p(block), 0, MEM_RELEASE)
                return None
            return [recv_addr, "recv↓", block, stolen]

        def _uninstall_entry_hook(self, addr, name, block, orig):
            """恢复被 E9 跳板覆盖的函数入口并回收代码块；入口不一致则保留。"""
            jump = b"\xE9" + struct.pack("<I", (block - (addr + 5)) & 0xFFFFFFFF)
            if read_mem(self.handle, addr, 5) != jump:
                self.replay_status.set("%s 入口与安装时不一致，钩子保留未卸载。" % name)
                return
            got = ctypes.c_size_t(0)
            if k32.WriteProcessMemory(self.handle, ctypes.c_void_p(addr), orig,
                                      len(orig), ctypes.byref(got)):
                k32.FlushInstructionCache(self.handle, ctypes.c_void_p(addr), len(orig))
            k32.VirtualFreeEx(self.handle, ctypes.c_void_p(block), 0, MEM_RELEASE)

        def start_capture(self):
            """依次钩住全部发包函数；单个失败跳过，全失败才取消勾选。"""
            self.capture_hooks = []
            self.capture_seen = {}
            self.send_hook_err = {}
            skipped = []
            for rva, name, len_arg, buf_arg in SEND_FUNCS:
                hook = self._install_hook(rva, name, len_arg, buf_arg)
                if hook:
                    self.capture_hooks.append(hook)
                else:
                    skipped.append(name)
            if not self.capture_hooks:
                self.capture_var.set(False)
                detail = "；".join("%s:%s" % (n, self.send_hook_err.get(n, "未知"))
                                   for n in skipped) or "未知"
                self.replay_status.set("抓包失败：全部发包函数未钩住（%s）。已自动取消勾选。" % detail)
                return
            msg = "抓包已开启：%s（%d 槽 × %d 字节）。之后本机发出的数据包都会进入列表。" \
                  % ("、".join(h[1] for h in self.capture_hooks), HOOK_SLOTS, HOOK_SLOT_DATA)
            if skipped:
                msg += "%s 未钩住（入口无法搬移）。" % "、".join(skipped)
            self.recv_hook = self._install_recv_hook()
            self.recv_seen = 0
            msg += "下行 recv 已钩。" if self.recv_hook \
                else "（recv 未钩：%s；仅上行抓包）" % (self.recv_hook_err or "未知原因")
            self.replay_status.set(msg)

        def stop_capture(self):
            hooks = self.capture_hooks
            recv_hook = self.recv_hook
            self.capture_hooks = []
            self.capture_seen = {}
            self.recv_hook = None
            self.recv_seen = 0
            if not self.handle:
                return
            if k32.WaitForSingleObject(self.handle, 0) != WAIT_TIMEOUT:
                return                      # 游戏已退出，钩子随进程消失
            if recv_hook:
                self._uninstall_entry_hook(*recv_hook)
            if not hooks:
                return    # 全失败后的取消勾选：保留「抓包失败」原因，不覆盖
            for rva, name, block, orig, _ra in hooks:
                send_addr = self.base + rva
                jump = b"\xE9" + struct.pack("<I", (block - (send_addr + 5)) & 0xFFFFFFFF)
                if read_mem(self.handle, send_addr, 5) != jump:
                    self.replay_status.set("%s 入口与安装时不一致，钩子保留未卸载。" % name)
                    continue
                got = ctypes.c_size_t(0)
                if k32.WriteProcessMemory(self.handle, ctypes.c_void_p(send_addr), orig,
                                          len(orig), ctypes.byref(got)):
                    k32.FlushInstructionCache(self.handle, ctypes.c_void_p(send_addr),
                                              len(orig))
                k32.VirtualFreeEx(self.handle, ctypes.c_void_p(block), 0, MEM_RELEASE)
            self.replay_status.set("抓包已关闭。")

        def capture_tick(self):
            if not self.capture_var.get():
                self.stop_capture()
                return
            if not self.handle:
                return
            if not self.capture_hooks:
                self.start_capture()
                return
            fresh = []
            for rva, name, block, _orig, _ra in self.capture_hooks:
                seen = self.capture_seen.get(rva, 0)
                counter = read_u32(self.handle, block + 0x1000 + HOOK_CTR_OFF)
                if counter is None:
                    continue
                if counter - seen > HOOK_SLOTS:
                    seen = counter - HOOK_SLOTS
                for v in range(max(seen, 0), counter):
                    slot = block + 0x1000 + HOOK_SLOTS_OFF + \
                        (v & (HOOK_SLOTS - 1)) * HOOK_SLOT_SIZE
                    blob = read_mem(self.handle, slot, HOOK_SLOT_SIZE)
                    if not blob:
                        continue
                    rec = parse_capture_slot(blob)
                    if rec["data"]:                       # 重放回声（marker=1）标注「我发」入列表
                        rec["time"] = time.strftime("%H:%M:%S")
                        rec["fn"] = rva
                        fresh.append(rec)
                self.capture_seen[rva] = max(seen, counter)
            if self.recv_hook:
                block = self.recv_hook[2]
                counter = read_u32(self.handle, block + 0x1000 + HOOK_CTR_OFF)
                if counter is not None:
                    if counter - self.recv_seen > HOOK_SLOTS:
                        self.recv_seen = counter - HOOK_SLOTS
                    for v in range(max(self.recv_seen, 0), counter):
                        slot = block + 0x1000 + HOOK_SLOTS_OFF + \
                            (v & (HOOK_SLOTS - 1)) * HOOK_SLOT_SIZE
                        blob = read_mem(self.handle, slot, HOOK_SLOT_SIZE)
                        if not blob:
                            continue
                        rec = parse_capture_slot(blob)
                        if rec["data"]:
                            rec["time"] = time.strftime("%H:%M:%S")
                            fresh.append(rec)         # id=0xFFFFFFFF → 列表显示「recv↓ 下行」
                    self.recv_seen = max(self.recv_seen, counter)
            if fresh:
                self.packets.extend(fresh)
                if len(self.packets) > 2000:
                    del self.packets[:len(self.packets) - 2000]
                self.refresh_packet_list()

        def refresh_packet_list(self):
            self.packet_list.delete(0, "end")
            self.view = []
            ids = parse_filter_ids(self.capture_filter.get())
            for seq, rec in enumerate(self.packets, 1):
                if ids and rec["id"] not in ids:
                    continue
                self.packet_list.insert("end", packet_line(seq, rec))
                self.view.append(rec)

        def clear_packets(self):
            self.packets = []
            self.refresh_packet_list()

        def save_packets(self):
            if not self.packets:
                self.replay_status.set("没有可保存的记录。")
                return
            import tkinter.filedialog as fd
            path = fd.asksaveasfilename(defaultextension=".json",
                                        initialfile="packets.json",
                                        filetypes=[("JSON", "*.json")])
            if not path:
                return
            dump = {"packets": [{"time": r["time"], "id": r["id"],
                                 "fn": r.get("fn", KILL_SEND_OFF),
                                 "a2": r.get("a2", 0), "a3": r.get("a3", 0),
                                 "a4": r.get("a4", 0),
                                 "hex": r["data"].hex()} for r in self.packets]}
            try:
                with open(path, "w", encoding="utf-8") as fp:
                    json.dump(dump, fp, ensure_ascii=False, indent=1)
            except OSError as exc:
                self.replay_status.set("保存失败：%s" % exc)
                return
            self.replay_status.set("已保存 %d 条记录到 %s。" % (len(self.packets), path))

        def load_packets(self):
            import tkinter.filedialog as fd
            path = fd.askopenfilename(filetypes=[("JSON", "*.json")])
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as fp:
                    items = json.load(fp).get("packets", [])
            except (OSError, ValueError, AttributeError):
                self.replay_status.set("载入失败：文件格式不正确。")
                return
            records = []
            for item in items[:400]:
                try:
                    data = parse_hex(str(item["hex"]))
                    if data:
                        records.append({"time": str(item.get("time", "")),
                                        "id": int(item["id"]), "mine": False,
                                        "fn": int(item.get("fn", KILL_SEND_OFF), 0) & 0xFFFFFFFF,
                                        "a2": int(item.get("a2", 0), 0) & 0xFFFFFFFF,
                                        "a3": int(item.get("a3", 0), 0) & 0xFFFFFFFF,
                                        "a4": int(item.get("a4", 0), 0) & 0xFFFFFFFF,
                                        "data": data})
                except (KeyError, TypeError, ValueError):
                    continue
            self.packets = records
            self.refresh_packet_list()
            self.replay_status.set("已载入 %d 条记录。" % len(records))

        def dump_code_sections(self):
            """导出主模块 PE 头与可执行/只读数据段到文件，供离线分析真正的发包路径。"""
            if not self.handle or not self.base:
                self.replay_status.set("导出代码段：请先连接游戏进程。")
                return
            dos = read_mem(self.handle, self.base, 0x40)
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0] \
                if dos and dos[:2] == b"MZ" else 0
            nt = read_mem(self.handle, self.base + e_lfanew, 0x800) if e_lfanew else b""
            secs = pe_sections(nt) if nt else []
            if not secs:
                self.replay_status.set("导出失败：主模块 PE 头解析失败。")
                return
            out_dir = os.path.dirname(os.path.abspath(sys.argv[0])) or "."
            manifest = {"module_base": self.base, "send_rva": KILL_SEND_OFF,
                        "sections": []}
            total = 0
            for name, va, vsize, chars in secs:
                want = bool(chars & 0x20000000) or name.lower() in (".rdata", ".rodata")
                entry = {"name": name, "va": va, "vsize": vsize,
                         "chars": chars, "dump": want}
                manifest["sections"].append(entry)
                if not want or not vsize:
                    continue
                blob = read_mem(self.handle, self.base + va, min(vsize, 0x4000000))
                entry["read"] = len(blob) if blob else 0
                if blob:
                    safe = "".join(ch if ch.isalnum() else "_" for ch in name) or "sec"
                    try:
                        with open(os.path.join(out_dir, "code_%s_%x.bin" % (safe, va)),
                                  "wb") as fp:
                            fp.write(blob)
                        total += len(blob)
                    except OSError as exc:
                        entry["error"] = str(exc)
            try:
                with open(os.path.join(out_dir, "code_manifest.json"), "w",
                          encoding="utf-8") as fp:
                    json.dump(manifest, fp, ensure_ascii=False, indent=1)
            except OSError as exc:
                self.replay_status.set("导出失败：%s" % exc)
                return
            self.replay_status.set("已导出 %.1f MB 代码段到 %s；把生成的 code_*.bin 和 "
                                   "code_manifest.json 一起发回即可。"
                                   % (total / 1048576.0, out_dir))

        def load_selected_packet(self):
            sel = self.packet_list.curselection()
            if not sel:
                self.replay_status.set("先在列表中选中一条记录。")
                return
            rec = self.view[sel[0]]
            self.edit_fn = rec.get("fn", KILL_SEND_OFF) & 0xFFFFFFFF
            self.edit_a2 = rec.get("a2", 0) & 0xFFFFFFFF
            self.edit_a3 = rec.get("a3", 0) & 0xFFFFFFFF
            self.edit_a4 = rec.get("a4", 0) & 0xFFFFFFFF
            self.replay_id.set(str(rec["id"]))
            self.hex_box.delete("1.0", "end")
            self.hex_box.insert("1.0", rec["data"].hex(" ").upper())
            self.replay_status.set("已载入 [%s] id=%d、%d 字节到编辑区；改完字节即可发送。"
                                   % (FN_NAMES.get(self.edit_fn, "?"), rec["id"],
                                      len(rec["data"])))

        def apply_hex_patch(self):
            parsed = self.payload_from_box()
            find = parse_hex(self.hex_find.get())
            replace = parse_hex(self.hex_replace.get())
            if parsed is None or find is None or not find or replace is None:
                self.replay_status.set("替换失败：包体或查找/替换 hex 非法。")
                return
            payload = parsed[1]
            count = payload.count(find)
            if not count:
                self.replay_status.set("包体中未找到查找内容。")
                return
            patched = patch_hex(payload, find, replace)
            self.hex_box.delete("1.0", "end")
            self.hex_box.insert("1.0", patched.hex(" ").upper())
            self.replay_status.set("已替换 %d 处，当前 %d 字节。" % (count, len(patched)))

        def apply_local_token(self):
            """把最近游戏握手包尾部的本局 token 替换进编辑区当前包体（0x47/0x9E），
            用户确认字节后再点「发送一次」——与手动验证成功的路径完全同构。"""
            parsed = self.payload_from_box()
            if parsed is None:
                return
            payload = parsed[1]
            token = None
            for rec in reversed(self.packets):
                if not rec.get("mine") and rec["id"] in (8071, 8291, 8121) \
                        and len(rec["data"]) >= 8:
                    token = rec["data"][-4:]
                    break
            if not token:
                self.replay_status.set("列表里没有游戏发的握手包（8071/8291/8121），先进一局。")
                return
            if len(payload) < 0xA2 or payload[0x47:0x4B] != payload[0x9E:0xA2]:
                if len(payload) < 8:
                    self.replay_status.set("包体太短，无法替换 token。")
                    return
                tail = payload[-4:]                 # 握手包：token 在尾部 4 字节
                if tail == b"\x00\x00\x00\x00":
                    self.replay_status.set("此包尾部无 token（全 0），无需替换，直接发送即可。")
                    return
                self.hex_box.delete("1.0", "end")
                self.hex_box.insert("1.0", (payload[:-4] + token).hex(" ").upper())
                self.replay_status.set("尾部 token %s → %s 已替换，确认后点「发送一次」。"
                                       % (tail.hex().upper(), token.hex().upper()))
                return
            old = payload[0x47:0x4B]
            if old == token:
                self.replay_status.set("token 已是本局（%s），无需替换。" % token.hex().upper())
                return
            patched = payload.replace(old, token)
            self.hex_box.delete("1.0", "end")
            self.hex_box.insert("1.0", patched.hex(" ").upper())
            self.replay_status.set("token %s → %s 已替换进编辑区（2 处），确认后点「发送一次」。"
                                   % (old.hex().upper(), token.hex().upper()))

        def payload_from_box(self):
            """编辑区内容 → (id, bytes)；允许空包体（如 8121/8286 空信号包）。"""
            raw = self.hex_box.get("1.0", "end").strip()
            if not raw:
                try:
                    return int(self.replay_id.get().strip(), 0), b""
                except ValueError:
                    self.replay_status.set("数据包 ID 非法（十进制或 0x 十六进制）。")
                    return None
            payload = parse_hex(raw)
            if payload is None or not payload:
                self.replay_status.set("包体为空或 hex 非法（成对十六进制，如 55 8B EC）。")
                return None
            if len(payload) > HOOK_SLOT_DATA:
                self.replay_status.set("包体超长：最多 %d 字节，当前 %d。"
                                       % (HOOK_SLOT_DATA, len(payload)))
                return None
            try:
                packet_id = int(self.replay_id.get().strip(), 0)
            except ValueError:
                self.replay_status.set("数据包 ID 非法（十进制或 0x 十六进制）。")
                return None
            return packet_id, payload

        def start_send(self, parsed):
            packet_id, payload = parsed
            if packet_id == 0xFFFFFFFF:
                self.replay_status.set("recv 行是下行记录，不能重放发送。")
                return False
            hook = next((h for h in self.capture_hooks if h[0] == self.edit_fn), None)
            marker = hook[2] + 0x1000 + HOOK_MARKER_OFF if hook else 0
            # 重放统一走函数入口：已钩住时经 stub 记一条「我发」回声便于确认，
            # 未钩住时入口即原函数（大厅A/B 是 E9 thunk，同样直达真身）
            fn_addr = self.base + self.edit_fn
            pushes = replay_pushes(self.edit_fn, packet_id, payload,
                                   self.edit_a2, self.edit_a3, self.edit_a4)
            if self.send_job.start(self.handle, fn_addr, pushes, payload, marker):
                return True
            self.replay_status.set("发送失败：远程线程创建失败（Win32 错误码 %d）。"
                                   % self.send_job.start_error)
            return False

        def start_send_rec(self, rec):
            """按记录自带的来源函数与参数原样入队发送（连发序列用）。"""
            self.edit_fn = rec.get("fn", KILL_SEND_OFF) & 0xFFFFFFFF
            self.edit_a2 = rec.get("a2", 0) & 0xFFFFFFFF
            self.edit_a3 = rec.get("a3", 0) & 0xFFFFFFFF
            self.edit_a4 = rec.get("a4", 0) & 0xFFFFFFFF
            return self.start_send((rec["id"], rec["data"]))

        def send_batch(self):
            """选中行与其后同一秒抓到的记录，按抓包顺序原样连发（结算簇重放）。"""
            if not self.handle:
                self.replay_status.set("请先选择进程并点「启动」。")
                return
            if self.send_job.busy():
                self.replay_status.set("上一次发送尚未结束，请稍候。")
                return
            if self.loop_var.get():
                self.replay_status.set("循环重放进行中，请先关闭再连发序列。")
                return
            sel = self.packet_list.curselection()
            if not sel:
                self.replay_status.set("先选中序列的第一包（如 4110），再点连发序列。")
                return
            stamp = self.view[sel[0]].get("time", "")
            batch = [self.view[sel[0]]]
            for rec in self.view[sel[0] + 1:]:
                if rec.get("time", "") != stamp or not rec["data"]:
                    break
                batch.append(rec)
            del batch[32:]
            if not batch[0]["data"]:
                self.replay_status.set("选中行没有包体，无法发送。")
                return
            self.batch_queue = list(batch)
            self.batch_total = len(batch)
            self.replay_status.set("连发序列已排队 %d 个（%s 同一秒，原样按序发送）。"
                                   % (len(batch), stamp or "无时间戳"))

        def one_key_settle(self):
            """一键结算：取最近握手包（8071/8291/8121）尾部的本局 token，替换进
            最近一条 4110 模板（0x47/0x9E 两处）后只发这一条 4110。
            实测旧局确认包（4115/2250/2251 等）在新对局重放会触发掉线，
            默认不带；需要实验时勾选「带确认包」才连同其后同一秒的包连发。"""
            if not self.handle:
                self.replay_status.set("请先选择进程并点「启动」。")
                return
            if self.send_job.busy() or self.batch_queue:
                self.replay_status.set("发送进行中，请稍候。")
                return
            if self.loop_var.get():
                self.replay_status.set("循环重放进行中，请先关闭。")
                return
            token = None
            for rec in reversed(self.packets):
                if not rec.get("mine") and rec["id"] in (8071, 8291, 8121) \
                        and len(rec["data"]) >= 8:
                    token = rec["data"][-4:]        # 游戏真实握手包尾部 4 字节 = 本局 token
                    break
            if not token:
                self.replay_status.set("列表里没有游戏发的握手包（8071/8291/8121），"
                                       "先开抓包进一局。")
                return
            sel = self.packet_list.curselection()
            idx = None
            if sel:
                cand = self.view[sel[0]]
                if cand["id"] == 4110 and len(cand["data"]) >= 0xA2 \
                        and not cand.get("mine"):
                    idx = next(i for i, r in enumerate(self.packets) if r is cand)
            if idx is None:
                idx = next((i for i in range(len(self.packets) - 1, -1, -1)
                            if self.packets[i]["id"] == 4110
                            and len(self.packets[i]["data"]) >= 0xA2
                            and not self.packets[i].get("mine")), None)
            if idx is None:
                self.replay_status.set("列表里没有游戏发的 4110 模板（需 ≥162 字节），"
                                       "先载入记录，或选中一条游戏发的 4110。")
                return
            tmpl = self.packets[idx]
            old = bytes(tmpl["data"][0x47:0x4B])
            if bytes(tmpl["data"][0x9E:0xA2]) != old:
                self.replay_status.set("4110 模板 token 位置校验失败（0x47/0x9E 不一致），"
                                       "请换一条 4110 模板。")
                return
            payload = tmpl["data"].replace(old, token)
            batch = [dict(tmpl, data=payload, a4=len(payload))]
            if self.settle_extras_var.get():
                for rec in self.packets[idx + 1:]:
                    if rec.get("time", "") != tmpl.get("time", "") or not rec["data"]:
                        break
                    batch.append(rec)
                del batch[32:]
            self.batch_queue = batch
            self.batch_total = len(batch)
            self.replay_status.set("一键结算排队 %d 个，模板 #%d（游戏包），token %s → %s%s。"
                                   % (len(batch), idx + 1, old.hex().upper(), token.hex().upper(),
                                      "（未变）" if token == old else
                                      ("，含确认包" if len(batch) > 1 else "，仅 4110")))

        def one_key_win(self):
            """一键胜利（实测组合，在要判负的号 10310 端运行）：
            先发 8071(94B) 再发 4110，两包均换上本局 token → 服务器判本号死亡、
            对手胜利结算并发奖。94B 取选中行或最近一条游戏发的 8071(94B)
            （尾部 4 字节换 token）；4110 取选中行或最近一条游戏发的 4110
            （0x47/0x9E 换 token，需死亡方模板 0x02=0000）。"""
            if not self.handle:
                self.replay_status.set("请先选择进程并点「启动」。")
                return
            if self.send_job.busy() or self.batch_queue:
                self.replay_status.set("发送进行中，请稍候。")
                return
            if self.loop_var.get():
                self.replay_status.set("循环重放进行中，请先关闭。")
                return
            token = None
            for rec in reversed(self.packets):
                if not rec.get("mine") and rec["id"] in (8071, 8291, 8121) \
                        and len(rec["data"]) >= 8:
                    token = rec["data"][-4:]
                    break
            if not token:
                self.replay_status.set("列表里没有游戏发的握手包（8071/8291/8121），"
                                       "先开抓包进一局。")
                return
            sel = self.packet_list.curselection()
            cand = self.view[sel[0]] if sel else None

            def pick(pred, what):
                if cand is not None and pred(cand) and not cand.get("mine"):
                    return next(i for i, r in enumerate(self.packets) if r is cand)
                return next((i for i in range(len(self.packets) - 1, -1, -1)
                             if pred(self.packets[i])
                             and not self.packets[i].get("mine")), None)

            i94 = pick(lambda r: r["id"] == 8071 and len(r["data"]) == 94,
                       "8071(94B)")
            i4110 = pick(lambda r: r["id"] == 4110 and len(r["data"]) >= 0xA2,
                         "4110")
            if i94 is None or i4110 is None:
                self.replay_status.set("缺模板：需要 8071(94B)%s 和死亡方 4110%s"
                                       "（载入死亡局记录，或选中对应行）。"
                                       % ("，已找到" if i94 is not None else "，未找到",
                                          "，已找到" if i4110 is not None else "，未找到"))
                return
            rec94 = self.packets[i94]
            old94 = bytes(rec94["data"][-4:])
            payload94 = rec94["data"][:-4] + token
            tmpl = self.packets[i4110]
            old = bytes(tmpl["data"][0x47:0x4B])
            if bytes(tmpl["data"][0x9E:0xA2]) != old:
                self.replay_status.set("4110 模板 token 位置校验失败（0x47/0x9E 不一致）。")
                return
            payload4110 = tmpl["data"].replace(old, token)
            batch = [dict(rec94, data=payload94, a4=len(payload94)),
                     dict(tmpl, data=payload4110, a4=len(payload4110))]
            self.batch_queue = batch
            self.batch_total = len(batch)
            self.replay_status.set("一键胜利排队 94B(#%d, token %s→%s) + 4110(#%d, "
                                   "token %s→%s)，按序连发。"
                                   % (i94 + 1, old94.hex().upper(), token.hex().upper(),
                                      i4110 + 1, old.hex().upper(), token.hex().upper()))

        def send_once(self):
            if not self.handle:
                self.replay_status.set("请先选择进程并点「启动」。")
                return
            if self.send_job.busy():
                self.replay_status.set("上一次发送尚未结束，请稍候。")
                return
            parsed = self.payload_from_box()
            if parsed:
                self.start_send(parsed)

        def replay_tick(self):
            if self.send_job.busy():
                if not self.handle:
                    return                      # 断开流程会在调用结束后接管
                result = self.send_job.poll(self.handle)
                if result == -1:
                    return
                if result == 1:
                    self.replay_sent += 1
                    if not self.batch_queue and self.batch_total:
                        self.replay_status.set("连发序列完成，共发送 %d 个。" % self.batch_total)
                        self.batch_total = 0
                    else:
                        self.replay_status.set("已发送 %d 次。" % self.replay_sent)
                elif result == 2:
                    self.loop_var.set(False)
                    self.batch_queue = []
                    self.batch_total = 0
                    self.replay_status.set("发送调用异常（原生函数内部出错），循环已停。")
                elif result == -3:
                    self.loop_var.set(False)
                    self.batch_queue = []
                    self.batch_total = 0
                    self.replay_status.set("发送调用超时，线程已强杀；建议重新连接游戏。")
                else:
                    self.loop_var.set(False)
                    self.batch_queue = []
                    self.batch_total = 0
                    self.replay_status.set("发送返回未知状态 %s，循环已停。" % result)
                return
            if self.batch_queue and not self.loop_var.get():
                rec = self.batch_queue.pop(0)
                self.replay_status.set("连发序列：发送 id=%d（队列剩 %d）…"
                                       % (rec["id"], len(self.batch_queue)))
                if not self.start_send_rec(rec):
                    self.batch_queue = []
                    self.batch_total = 0
                return
            if not self.loop_var.get() or not self.handle:
                return
            if self.loop_left == 0:
                self.loop_var.set(False)
                self.replay_status.set("循环重放完成，共发送 %d 次。" % self.replay_sent)
                return
            interval = parse_ms(self.loop_interval.get(), 1000) or 1000
            if self.loop_last and now_ms() - self.loop_last < interval:
                return
            parsed = self.payload_from_box()
            if parsed is None:
                self.loop_var.set(False)
                return
            if self.loop_left > 0:
                self.loop_left -= 1
            self.loop_last = now_ms()
            if not self.start_send(parsed):
                self.loop_var.set(False)

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
            ready = bool(self.actor)
            self.suicide_armed_at = arm_delay(ready, self.suicide_var.get(),
                                              self.suicide_armed_at)
            self.kill_armed_at = arm_delay(ready, self.kill_var.get(),
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
            self.capture_tick()
            self.replay_tick()
            self.move_tick()
            self.click_tick()
            self.mem_tick()
            self.root.after(30, self.auto_loop)

        def on_mem_toggle(self):
            self.mem_last_clean = now_ms()  # 勾选即重新计时
            self.save_settings()

        def clean_memory(self):
            """EmptyWorkingSet：请系统把游戏工作集页换出。治标不治本——泄漏块仍在，
            但任务管理器内存数字回落、系统内存压力缓解。"""
            if not self.handle:
                self.mem_status.set("未连接游戏，无法清理。")
                return
            if psapi().EmptyWorkingSet(self.handle):
                self.mem_status.set("已请求系统裁剪游戏工作集；游戏首次访问被换出页面时可能短暂卡顿。")
            else:
                self.mem_status.set("清理失败（错误码 %d）。" % ctypes.get_last_error())

        def elevate_self(self):
            """以管理员身份重启本程序（UAC 弹窗）；当前实例随后退出。"""
            if is_admin():
                self.status.set("当前已是管理员权限，无需提权。")
                return
            if elevate():
                self.stop_capture()
                self.status.set("正在以管理员身份重启…")
                self.root.after(300, self.root.destroy)
            else:
                self.status.set("提权被取消或失败。")

        def mem_tick(self):
            if not self.mem_auto.get() or not self.handle:
                return
            interval = parse_minutes(self.mem_every.get()) * 60000
            if now_ms() - self.mem_last_clean >= interval:
                self.mem_last_clean = now_ms()
                psapi().EmptyWorkingSet(self.handle)

        def on_close(self):
            if self.move_pressed:
                send_move_key(self.move_hwnd,
                              MOVE_KEYS.get(self.move_key.get(), 0x44), False)
                self.move_pressed = False
            if self.pick_after_id:
                self.root.after_cancel(self.pick_after_id)
                self.pick_after_id = 0
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
