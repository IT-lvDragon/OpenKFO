#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""属性助手（单机版）—— 游戏运行后可选启动的属性修改脚本。

原理与 tools/game-mod/main.cpp 一致：外部进程读写（ReadProcessMemory /
WriteProcessMemory），不注入 DLL、不修改任何游戏文件。取消勾选、停止或
游戏退出时，尽量恢复启用前的原始值。

用法：
  python AttributeAssist.py           打开界面：选择游戏进程 → 点击“启动”
  python AttributeAssist.py --self-test  无界面自检（校验角色定位与恢复逻辑）
  python AttributeAssist.py --list    诊断：打印全部进程名并标记游戏进程

仅限本地单机环境使用；写入前会校验客户端 SHA-256，
与本机已核对的 gfxz.dat 不符时拒绝连接。
"""

import ctypes
import hashlib
import json
import math
import os
import struct
import sys
import time
from ctypes import wintypes

# ---- 已核对证据（与 tools/game-mod/main.cpp 一致）----
CLIENT_HASHES = {
    "1B7C8676E778C7BD47F55184F927338DA3CF70C6AA5F0BEB59869EA0F0AC9D4E",
}
GAME_NAMES = ("gfxz.dat", "gfld.dat")
BASE_FALLBACK = 0x400000

MANAGER_PTR = 0x13C8708   # base+0x13C8708 -> 战斗对象管理器
INFO_PTR = 0x13C86FC      # base+0x13C86FC -> 自己的信息（+0x18 为 uid）
UID_OFFSET = 0xC90        # actor+0xC90  -> uid（uint64）
STATE_OFFSET = 0x1A6C     # actor+0x1A6C -> state 指针

# 功能表：use_state=True 时偏移基于 state 指针，否则基于 actor 指针（与 main.cpp address() 一致）。
# is_int=True 为开关型（固定写 1）；否则按 0–999 浮点写入，实际值 = 输入 × scale。
FEATURES = [
    dict(name="怒气倍率（999≈无限怒气）", offset=0x80, use_state=True, is_int=False, initial="999", scale=1.0),
    dict(name="无敌", offset=0x1780, use_state=False, is_int=True, initial="1"),
    dict(name="霸体", offset=0x64, use_state=True, is_int=True, initial="1"),
    dict(name="反伤值", offset=0x1BD0, use_state=False, is_int=False, initial="1", scale=1.0),
    dict(name="防御值", offset=0x78, use_state=True, is_int=False, initial="1", scale=1.0),
    dict(name="吸血值（原版输入单位）", offset=0x6C, use_state=True, is_int=False, initial="10", scale=0.1),
]

PROCESS_RIGHTS = 0x0400 | 0x0008 | 0x0010 | 0x0020 | 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
INVALID_HANDLE = ctypes.c_size_t(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.GetProcessId.restype = wintypes.DWORD
k32.GetProcessId.argtypes = [wintypes.HANDLE]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD)]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
k32.GetCurrentProcess.restype = wintypes.HANDLE


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                               wintypes.DWORD, wintypes.DWORD]
k32.VirtualFreeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
k32.VirtualProtectEx.restype = wintypes.BOOL
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.FlushInstructionCache.restype = wintypes.BOOL
k32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
k32.CreateRemoteThread.restype = wintypes.HANDLE
k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                                   ctypes.POINTER(wintypes.DWORD)]


# ---- 内存读写 ----
def read_mem(handle, address, size):
    if not handle or address < 0x10000:
        return None
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, address, buf, size, ctypes.byref(got)) or got.value != size:
        return None
    return buf.raw


def read_u32(handle, address):
    raw = read_mem(handle, address, 4)
    return struct.unpack("<I", raw)[0] if raw else None


def read_u64(handle, address):
    raw = read_mem(handle, address, 8)
    return struct.unpack("<Q", raw)[0] if raw else None


def write_u32(handle, address, value):
    if not handle or address < 0x10000:
        return False
    got = ctypes.c_size_t(0)
    if not k32.WriteProcessMemory(handle, address, struct.pack("<I", value & 0xFFFFFFFF), 4,
                                  ctypes.byref(got)) or got.value != 4:
        return False
    return True


def write_mem(handle, address, data):
    if not handle or address < 0x10000:
        return False
    got = ctypes.c_size_t(0)
    return bool(k32.WriteProcessMemory(handle, address, bytes(data), len(data),
                                       ctypes.byref(got))) and got.value == len(data)


def resolve_actor(handle, manager, uid):
    """按 main.cpp 的证据在管理器红黑树里定位 uid 对应角色，返回 (actor, state, uid)。"""
    if not manager or not uid:
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
        if key >= 40 or not value or read_u64(handle, value + UID_OFFSET) != uid:
            continue
        state = read_u32(handle, value + STATE_OFFSET)
        if not state:
            return None
        return (value, state, uid)
    return None


# ---- 秒杀与中毒：移植自 tools/game-mod/kill.h ----
KILL_SEND_OFF = 0x63FBB0              # 发包函数，序言 0x51EC8B55
KILL_DAMAGE_OFF = 0x5F29F0            # thiscall 伤害调用，序言 0x83EC8B55
KILL_HEALTH_OFF = 0x5E45B0            # 目标血量读取，序言 0x81EC8B55
POISON_APPLY_OFF = 0x5C69C0           # 效果施加，序言 0x81EC8B55
POISON_NOTIFY_OFF = 0x5C5580          # 效果通知，序言 0x83EC8B55
POISON_SRC_NOTIFY_OFF = 0x5E7480      # 来源侧通知，序言 0x51EC8B55
NPC_TYPE_OFFSET = 0xEF6B00            # CNpc RTTI type descriptor（本机 gfxz.dat）


def now_ms():
    return int(time.monotonic() * 1000)


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


def is_npc(handle, base, actor):
    """actor=(ptr,state,uid)；CNpc RTTI 判定，排除玩家/宠物。返回 (ok, vftable)。"""
    vt = read_u32(handle, actor[0])
    if not vt:
        return False, 0
    col = read_u32(handle, vt - 4)
    if not col:
        return False, 0
    type_ = read_u32(handle, col + 12)
    if not type_:
        return False, 0
    return type_ == base + NPC_TYPE_OFFSET, vt


def make_kill(handle, base, own, enemy, poison=False):
    """移植 makeKill：全部前置检查通过后生成调用参数；失败返回 None。
    own/enemy 为 (ptr, state, uid)。"""
    if enemy[2] == own[2] or not enemy[1]:
        return None
    if read_u32(handle, own[0] + 0x7C) != 1 or read_u32(handle, enemy[0] + 0x7C) != 1:
        return None
    if not read_u32(handle, own[0] + 0xCE0) or not read_u32(handle, enemy[0] + 0xCE0):
        return None
    own_team = read_u32(handle, own[0] + 0x28)
    enemy_team = read_u32(handle, enemy[0] + 0x28)
    if own_team is None or enemy_team is None or (not poison and own_team == enemy_team):
        return None
    manager = read_u32(handle, base + MANAGER_PTR)
    if not manager:
        return None
    context = read_u64(handle, manager + 0x311)
    if not context:
        return None

    k = {"poison": poison, "source": own[0], "target": enemy[0], "state": enemy[1],
         "send": base + KILL_SEND_OFF, "damage": base + KILL_DAMAGE_OFF,
         "health": base + KILL_HEALTH_OFF, "notify": base + POISON_NOTIFY_OFF,
         "source_notify": base + POISON_SRC_NOTIFY_OFF,
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
        return None
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
    if poison:
        ok, vt = is_npc(handle, base, enemy)
        if not ok:
            return None
        k["damage"] = base + POISON_APPLY_OFF
        pkt = bytearray(94)  # 实际发送长度 87，高位保持 0
        pkt[4:12] = struct.pack("<Q", own[2])
        pkt[39:47] = struct.pack("<Q", enemy[2])
        pkt[47:55] = struct.pack("<Q", own[2])
        pkt[55:59] = struct.pack("<I", 1)        # code
        pkt[59:63] = struct.pack("<I", 1)        # level
        pkt[63:67] = struct.pack("<I", 3000)     # duration
        pkt[75:79] = struct.pack("<I", 1)        # operation
        pkt[79:87] = struct.pack("<Q", context)
        k["packet"] = pkt
        effect = k["effect"]
        effect[0], effect[1], effect[2], effect[4] = 1, 1, 3000, own[2] & 0xFFFFFFFF
        effect[5], effect[6] = (own[2] >> 32) & 0xFFFFFFFF, 1
        weapon_slot = read_u32(handle, enemy[0] + 0xCB0)
        if weapon_slot is None:
            return None
        weapon = read_u32(handle, enemy[0] + (0xCC0 if weapon_slot else 0xCC4))
        if weapon:
            weapon_info = read_u32(handle, weapon + 0x37C)
            if not weapon_info:
                return None
            effect[7] = weapon_info
        guards += [(enemy[0], vt), (enemy[1], enemy[0])]

    # 函数序言与连接时的文件哈希同样作为版本门禁
    checks = [(k["send"], 0x51EC8B55), (k["health"], 0x81EC8B55),
              (k["damage"], 0x81EC8B55 if poison else 0x83EC8B55)]
    if poison:
        checks += [(k["notify"], 0x83EC8B55), (k["source_notify"], 0x51EC8B55)]
    for addr, expect in checks:
        if read_u32(handle, addr) != expect:
            return None
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
        self.patch(p, target - p - 4)

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
    if k["poison"]:
        c.push(1)
        c.push(data_base + 160)
        c.bytes_((0xB9,))
        c.word(k["state"])
        c.call(k["damage"])
        c.bytes_((0x85, 0xC0, 0x0F, 0x84))
        stale.append(c.hole())
    c.push(0)
    c.push(0)
    c.push(87 if k["poison"] else 94)
    c.push(data_base)
    c.push(8150 if k["poison"] else 8121)
    c.call(k["send"])
    c.bytes_((0x83, 0xC4, 0x14))
    # 发包后复查：并发换局时不得触碰旧角色
    for g in k["guards"]:
        c.bytes_((0x81, 0x3D))
        c.word(g[0])
        c.word(g[1])
        c.bytes_((0x0F, 0x85))
        stale.append(c.hole())
    rejected = 0
    if k["poison"]:
        c.push(data_base + 160)
        c.bytes_((0xB9,))
        c.word(k["state"])
        c.call(k["notify"])
        c.push(1)
        c.push(k["source"])
        c.bytes_((0xB9,))
        c.word(k["target"])
        c.call(k["source_notify"])
    else:
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
    if rejected:
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

    def busy(self):
        return bool(self.thread)

    def start(self, process, k):
        if self.thread:
            return False
        block = k32.VirtualAllocEx(process, None, 8192, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE) or 0
        if not block:
            return False
        if block > 0xFFFFFFFF:  # WoW64 目标必须落在 32 位地址空间
            k32.VirtualFreeEx(process, block, 0, MEM_RELEASE)
            return False
        code = kill_code(block, block + 4096, k)
        ok = (len(code) <= 4096 and write_mem(process, block, code)
              and write_mem(process, block + 4096, k["packet"])
              and write_mem(process, block + 4096 + 160,
                            struct.pack("<8I", *k["effect"])))
        previous = wintypes.DWORD(0)
        if ok:
            ok = bool(k32.VirtualProtectEx(process, block, 4096, PAGE_EXECUTE_READ,
                                           ctypes.byref(previous)))
        if ok:
            ok = bool(k32.FlushInstructionCache(process, block, len(code)))
        thread = 0
        if ok:
            thread = k32.CreateRemoteThread(process, None, 0, block, None, 0, None) or 0
        if not thread:
            k32.VirtualFreeEx(process, block, 0, MEM_RELEASE)
            return False
        self.thread, self.block, self.started = thread, block, time.monotonic()
        return True

    def poll(self, process):
        if not self.thread:
            return -2
        if k32.WaitForSingleObject(self.thread, 0) != WAIT_OBJECT_0:
            return -1
        result = read_u32(process, self.block + 4096 + 128)
        k32.CloseHandle(self.thread)
        k32.VirtualFreeEx(process, self.block, 0, MEM_RELEASE)
        self.thread, self.block = 0, 0
        return -2 if result is None else result


def round_due(now, previous, busy, paused, wanted):
    return (not busy) and (not paused) and bool(wanted) and now - previous >= 400


# ---- 功能执行与恢复 ----
class Feature:
    def __init__(self, spec):
        self.name = spec["name"]
        self.offset = spec["offset"]
        self.use_state = spec["use_state"]
        self.is_int = spec["is_int"]
        self.initial = spec["initial"]
        self.scale = spec.get("scale", 1.0)
        self.saved = False
        self.original = 0
        self.last = 0


def feature_address(actor, feature):
    ptr, state, _uid = actor
    return (state if feature.use_state else ptr) + feature.offset


def feature_current(handle, actor, feature):
    return read_u32(handle, feature_address(actor, feature))


def feature_desired(text, feature):
    """与 main.cpp input() 一致：整数型固定 1，浮点型 0–999。"""
    if feature.is_int:
        return 1, True
    try:
        value = float(str(text).strip())
    except ValueError:
        return 0, False
    if not math.isfinite(value) or value < 0 or value > 999:
        return 0, False
    return struct.unpack("<I", struct.pack("<f", value * feature.scale))[0], True


def feature_restore(handle, actor, feature):
    """恢复原值；游戏自己改过的字段保持不动，角色已切换则只清标记。"""
    if not feature.saved:
        return True
    if actor is None:
        feature.saved = False
        return True
    current = feature_current(handle, actor, feature)
    if current is None:
        return False
    if current != feature.last:
        feature.saved = False
        return True
    if write_u32(handle, feature_address(actor, feature), feature.original):
        feature.saved = False
        return True
    return False


def format_value(bits, is_int):
    if is_int:
        return str(bits)
    return "%.4g" % struct.unpack("<f", struct.pack("<I", bits))[0]


# ---- 进程枚举 ----
LAST_SNAP_ERROR = ""


def find_processes(want_all=False):
    """枚举进程；want_all=True 返回全部进程（诊断用）。失败时写入 LAST_SNAP_ERROR。"""
    global LAST_SNAP_ERROR
    out = []
    LAST_SNAP_ERROR = ""
    snap = 0
    for _attempt in range(2):  # 快照偶发 ERROR_BAD_LENGTH，重试一次
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) or 0
        if snap and snap != INVALID_HANDLE:
            break
        LAST_SNAP_ERROR = f"CreateToolhelp32Snapshot 失败（错误码 {ctypes.get_last_error()}）"
        snap = 0
    if not snap:
        return out
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not k32.Process32FirstW(snap, entry):
            LAST_SNAP_ERROR = (f"Process32FirstW 失败（错误码 {ctypes.get_last_error()}，"
                               f"{ctypes.sizeof(ctypes.c_void_p) * 8} 位 Python，结构体大小 {entry.dwSize}）")
            return out
        while True:
            name = entry.szExeFile
            if want_all or name.lower() in GAME_NAMES:
                out.append((entry.th32ProcessID, name))
            if not k32.Process32NextW(snap, entry):
                break
    finally:
        k32.CloseHandle(snap)
    return out


def list_processes():
    """--list 诊断：打印全部进程名，便于核对游戏实际 exe 名。"""
    procs = find_processes(want_all=True)
    if not procs:
        print(LAST_SNAP_ERROR or "进程列表为空。")
        return 1
    matches = [(pid, name) for pid, name in procs if name.lower() in GAME_NAMES]
    print(f"共 {len(procs)} 个进程；匹配游戏：{len(matches)} 个")
    for pid, name in sorted(procs):
        mark = "   <== 游戏进程" if name.lower() in GAME_NAMES else ""
        print(f"  {name}  ·  PID {pid}{mark}")
    if not matches:
        print("未发现 gfxz.dat / gfld.dat —— 请确认游戏已启动；若游戏 exe 名不同，"
              "把上面列表里的名字发我以加入匹配。")
    return 0


def module_base(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) or 0
    if not snap or snap == INVALID_HANDLE:
        return 0
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    base = 0
    if k32.Module32FirstW(snap, entry) and entry.modBaseAddr:
        base = int(entry.modBaseAddr)
    k32.CloseHandle(snap)
    return base


def query_image_path(handle):
    size = wintypes.DWORD(32768)
    buf = ctypes.create_unicode_buffer(size.value)
    if not k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        return None
    return buf.value


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


# ---- 自检：无 GUI，校验定位/读写/恢复语义 ----
def self_test():
    # Toolhelp 结构体必须与 Windows 头文件布局完全一致，否则 Process32First 报错 24
    assert ctypes.sizeof(PROCESSENTRY32W) == (568 if ctypes.sizeof(ctypes.c_void_p) == 8 else 556), \
        f"PROCESSENTRY32W 尺寸异常: {ctypes.sizeof(PROCESSENTRY32W)}"
    assert ctypes.sizeof(MODULEENTRY32W) == (1080 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1064), \
        f"MODULEENTRY32W 尺寸异常: {ctypes.sizeof(MODULEENTRY32W)}"

    buffer = k32.VirtualAlloc(None, 0x1400000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not buffer:
        return 1
    handle = k32.GetCurrentProcess()
    base = buffer

    def put(address, value):
        assert write_u32(handle, address, value)

    manager, head, node, actor, state, info = (base + 0x1000, base + 0x2000, base + 0x2100,
                                               base + 0x3000, base + 0x6000, base + 0x7000)
    uid = 123456789
    write_u32(handle, actor + UID_OFFSET, uid)
    write_u32(handle, (actor + UID_OFFSET + 4), 0)
    put(actor + STATE_OFFSET, state)
    put(manager + 0x2F0, head)
    put(head + 4, node)
    put(node, head)          # left
    put(node + 8, head)      # right
    put(node + 12, 0)        # key=0 <40
    put(node + 16, actor)    # value

    ok = resolve_actor(handle, manager, uid) == (actor, state, uid)
    ok = ok and resolve_actor(handle, manager, uid + 1) is None
    put(node, node)          # 环形坏树必须终止
    ok = ok and resolve_actor(handle, manager, uid + 1) is None
    put(node, head)

    put(state + 0x80, 17)
    ok = ok and read_u32(handle, state + 0x80) == 17
    ok = ok and write_u32(handle, state + 0x80, 22) and read_u32(handle, state + 0x80) == 22

    f = Feature(FEATURES[0])
    f.saved, f.original, f.last = True, 17, 22
    ok = ok and feature_restore(handle, (actor, state, uid), f) \
        and read_u32(handle, state + 0x80) == 17 and not f.saved
    write_u32(handle, state + 0x80, 33)  # 游戏自己改过 → 不回写
    f.saved, f.original, f.last = True, 17, 22
    ok = ok and feature_restore(handle, (actor, state, uid), f) \
        and read_u32(handle, state + 0x80) == 33
    f.saved, f.original, f.last = True, 17, 22
    ok = ok and feature_restore(handle, None, f) and not f.saved  # 角色已切换

    rage = Feature(FEATURES[0])
    ok = ok and feature_desired("999", rage) == (0x4479C000, True)
    ok = ok and not feature_desired("abc", rage)[1]
    ok = ok and not feature_desired("1000", rage)[1]
    inv = Feature(FEATURES[1])
    ok = ok and feature_desired("任意", inv) == (1, True)

    # 基址映射必须与 main.cpp address() 完全一致（state 还是 actor 指针）
    bases = [feature_address((actor, state, uid), Feature(spec)) for spec in FEATURES]
    ok = ok and bases == [state + 0x80, actor + 0x1780, state + 0x64,
                          actor + 0x1BD0, state + 0x78, state + 0x6C]
    lifesteal = Feature(FEATURES[5])
    ok = ok and feature_desired("10", lifesteal) == (0x3F800000, True)  # 10 × 0.1 = 1.0f

    # ---- 秒杀/中毒（kill.h 移植）：本进程合成内存，不注入任何代码 ----
    enemy, enemy_state = base + 0x9000, base + 0x9100
    node2, weapon, vtable, col = base + 0x2200, base + 0x9200, base + 0x9300, base + 0x9400
    enemy_uid = uid + 1
    put(node + 8, node2)     # 树：own → enemy
    put(node2, head)         # node2.left
    put(node2 + 8, head)     # node2.right
    put(node2 + 12, 1)       # key=1 <40
    put(node2 + 16, enemy)
    write_u32(handle, enemy + UID_OFFSET, enemy_uid)
    write_u32(handle, enemy + UID_OFFSET + 4, 0)
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

    # 函数序言未写入 → 全部拒绝
    ok = ok and make_kill(handle, base, (actor, state, uid), (enemy, enemy_state, enemy_uid)) is None
    prologues = {0x63FBB0: 0x51EC8B55, 0x5E45B0: 0x81EC8B55, 0x5F29F0: 0x83EC8B55,
                 0x5C69C0: 0x81EC8B55, 0x5C5580: 0x83EC8B55, 0x5E7480: 0x51EC8B55}
    for off, value in prologues.items():
        put(base + off, value)

    own_a, enemy_a = (actor, state, uid), (enemy, enemy_state, enemy_uid)
    # 同队拒绝秒杀
    put(enemy + 0x28, 1)
    ok = ok and make_kill(handle, base, own_a, enemy_a) is None
    put(enemy + 0x28, 2)
    k = make_kill(handle, base, own_a, enemy_a)
    ok = ok and bool(k)
    if k:
        ok = ok and k["bits"] == 0x461C3C00 and k["packet"][65] == 1 and k["packet"][55] == 7
        ok = ok and struct.unpack_from("<Q", k["packet"], 39)[0] == enemy_uid
        ok = ok and struct.unpack_from("<Q", k["packet"], 86)[0] == 0x1234567800000007
        ok = ok and len(k["guards"]) == 13

    # 中毒：RTTI 链不匹配拒绝；命中 CNpc 后字段齐全
    put(enemy, vtable)
    put(vtable - 4, col)
    put(col + 12, base + 0xEF6B01)  # 非 CNpc
    ok = ok and make_kill(handle, base, own_a, enemy_a, True) is None
    put(col + 12, base + 0xEF6B00)
    put(enemy + 0xCB0, 0)    # 武器槽 0 → 从 +0xCC4 取
    put(enemy + 0xCC4, weapon)
    put(weapon + 0x37C, 0x55AA)
    p = make_kill(handle, base, own_a, enemy_a, True)
    ok = ok and bool(p)
    if p:
        ok = ok and p["damage"] == base + POISON_APPLY_OFF
        ok = ok and struct.unpack_from("<I", p["packet"], 55)[0] == 1
        ok = ok and struct.unpack_from("<I", p["packet"], 59)[0] == 1
        ok = ok and struct.unpack_from("<I", p["packet"], 63)[0] == 3000
        ok = ok and struct.unpack_from("<I", p["packet"], 75)[0] == 1
        ok = ok and struct.unpack_from("<Q", p["packet"], 79)[0] == 0x1234567800000007
        ok = ok and p["effect"] == [1, 1, 3000, 0, uid & 0xFFFFFFFF, 0, 1, 0x55AA]
        ok = ok and len(p["guards"]) == 15
        ok = ok and p["guards"][-2] == (enemy, vtable) \
            and p["guards"][-1] == (enemy_state, enemy)

    # shellcode 结构完整性（语义已由 C++ killSelfTest 在真机上验证）
    code = kill_code(0x10000000, 0x20000000, k or p)
    tail = code.rfind(b"\xC2\x04\x00")
    ok = ok and len(code) <= 4096 and code[0] == 0x55 and code[1] == 0x8B and code[2] == 0xEC
    ok = ok and tail != -1 and struct.unpack_from("<I", code, 11)[0] == 0x10000000 + tail + 3
    ok = ok and code.count(struct.pack("<I", 0x20000000 + 128)) == 4  # 状态码 1/2/4/3 写回

    ok = ok and not round_due(1399, 1000, False, False, True)
    ok = ok and round_due(1400, 1000, False, False, True)
    ok = ok and not round_due(1800, 1000, True, False, True)
    ok = ok and not round_due(1800, 1000, False, True, True)
    ok = ok and not round_due(1800, 1000, False, False, False)

    stamps = []
    npc = (enemy, enemy_state, enemy_uid)

    def stamp(a, when):
        for i, s in enumerate(stamps):
            if s[2] == a[2]:
                stamps[i] = (a[0], a[1], a[2], when)
                return
        if len(stamps) >= 128:
            stamps.pop(0)
        stamps.append((a[0], a[1], a[2], when))

    def due(a, when):
        for ptr, st, uid_, t in stamps:
            if ptr == a[0] and st == a[1] and uid_ == a[2]:
                return when - t >= 4000
        return True

    stamp(npc, 1000)
    ok = ok and not due(npc, 4999) and due(npc, 5000)
    npc2 = (enemy, enemy_state + 1, enemy_uid)  # state 变化 → 视为新目标
    ok = ok and due(npc2, 1001)

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
            # 秒杀/中毒调度状态（对应 kill.h 全局）
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
            self.poison_stamps = []  # (ptr, state, uid, now_ms)

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
                    entry.state(["disabled"])
                entry.bind("<KeyRelease>", lambda _e: self.save_settings())
                entry.grid(row=i, column=1, padx=8)
                ttk.Label(body, text="当前值").grid(row=i, column=2)
                value = tk.StringVar(value="—")
                ttk.Label(body, textvariable=value, width=12).grid(row=i, column=3, sticky="w")
                self.rows.append((enabled, entry, value))

            self.status = tk.StringVar(
                value="游戏运行后选择进程点击“启动”；换局自动继续，取消勾选会恢复原值。")
            ttk.Label(root, textvariable=self.status, wraplength=520,
                      justify="left").pack(fill="x", padx=12, pady=(4, 12))

            killbox = ttk.LabelFrame(root, text="自动战斗（游戏原生调用：SEH 守卫 + 轮次复查）")
            killbox.pack(fill="x", padx=12, pady=(0, 4))
            self.kill_var = tk.BooleanVar(value=False)
            self.poison_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(killbox, text="自动秒杀敌方（9999 伤害，每 400ms 一轮）",
                            variable=self.kill_var,
                            command=self.save_settings).grid(row=0, column=0, sticky="w",
                                                             padx=8, pady=4)
            ttk.Checkbutton(killbox, text="NPC 中毒（1 级 / 3 秒，每 4 秒补一次）",
                            variable=self.poison_var,
                            command=self.save_settings).grid(row=0, column=1, sticky="w",
                                                             padx=8, pady=4)
            self.kill_status = tk.StringVar(value="进入有敌方角色的战斗后自动执行。")
            ttk.Label(killbox, textvariable=self.kill_status, wraplength=520,
                      justify="left").grid(row=1, column=0, columnspan=2, sticky="w",
                                           padx=8, pady=(0, 6))

            self.load_settings()
            self.refresh()
            root.after(100, self.tick)
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
                entry.delete(0, "end")
                entry.insert(0, str(item.get("value", f.initial)))
            self.kill_var.set(bool(data.get("kill", False)))
            self.poison_var.set(bool(data.get("poison", False)))

        def save_settings(self):
            path = settings_path()
            if not path:
                return
            data = {"features": [{"enabled": self.rows[i][0].get(),
                                  "value": self.rows[i][1].get()}
                                 for i in range(len(self.features))],
                    "kill": self.kill_var.get(),
                    "poison": self.poison_var.get()}
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
                self.status.set(LAST_SNAP_ERROR + "；每秒自动重试。")
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
            if not path or file_sha256(path) not in CLIENT_HASHES:
                k32.CloseHandle(handle)
                self.status.set("此客户端版本尚未核对地址，已拒绝写入。目前支持本机这份 gfxz.dat。")
                return
            base = module_base(pid) or BASE_FALLBACK
            self.handle, self.base, self.actor = handle, base, None
            self.auto_fault = False
            self.status.set("已启动。沿用勾选设置，换局自动继续，无需重复连接。")

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
                    self.status.set("等待秒杀/中毒调用结束后断开；勾选已保留。")
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
                    self.actor = None
                    if self.kill_job.busy():
                        self.kill_job.poll(self.handle)  # 线程随进程终止，仅回收内存
                    self.restore_all()
                    k32.CloseHandle(self.handle)
                    self.handle, self.base, self.actor = 0, 0, None
                    self.auto_fault = False
                    self.disconnect_pending = False
                    self.kill_queue.clear()
                    self.kill_next = 0
                    self.current_target = None
                    for _enabled, _entry, value in self.rows:
                        value.set("—")
                    self.status.set("游戏进程已退出，已停止操作；勾选保留。选择新进程后点击启动。")
                else:
                    self.enforce()
                    self.auto_tick()
                    if self.disconnect_pending and not self.kill_busy():
                        self.disconnect_pending = False
                        self.stop()  # 当前调用已返回，完成恢复与断开
            elif self.disconnect_pending and not self.kill_busy():
                self.disconnect_pending = False
                self.stop()
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

        def poison_due(self, actor, now):
            for ptr, state, uid, when in self.poison_stamps:
                if ptr == actor[0] and state == actor[1] and uid == actor[2]:
                    return now - when >= 4000
            return True

        def stamp_poison(self, actor, now):
            for i, stamp in enumerate(self.poison_stamps):
                if stamp[2] == actor[2]:
                    self.poison_stamps[i] = (actor[0], actor[1], actor[2], now)
                    return
            if len(self.poison_stamps) >= 128:
                self.poison_stamps.pop(0)
            self.poison_stamps.append((actor[0], actor[1], actor[2], now))

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
                    if target[1]:
                        self.stamp_poison(target[0], now_ms())
                    self.kill_done += 1
                else:
                    self.kill_skipped += 1
                    if result not in (2, 4) and result != -2:
                        self.kill_cancel = True
                        self.auto_fault = True
                self.current_target = None
            while not self.kill_cancel and self.kill_next < len(self.kill_queue):
                actor, poison = self.kill_queue[self.kill_next]
                self.kill_next += 1
                want = self.poison_var.get() if poison else self.kill_var.get()
                if not want:
                    self.kill_skipped += 1
                    continue
                k = make_kill(self.handle, self.base, self.actor, actor, poison) \
                    if self.actor else None
                if not k:
                    self.kill_skipped += 1
                    continue
                if not self.kill_job.start(self.handle, k):
                    self.kill_cancel = True
                    self.auto_fault = True
                    self.kill_skipped += 1
                    break
                self.current_target = (actor, poison)
                return
            self.kill_queue.clear()
            self.kill_next = 0
            if self.auto_fault:
                self.kill_status.set("自动操作因调用失败/异常暂停。勾选已保留；检查后重新连接恢复。")
                return
            state = "已停止" if self.kill_cancel else "本次结束"
            self.kill_status.set(
                f"{state}：调用完成 {self.kill_done}，跳过/失败 {self.kill_skipped}。请在游戏中确认效果。")

        def start_kill(self):
            if self.kill_busy() or self.auto_fault:
                return
            if not self.handle or not self.actor or not self.actor[1]:
                self.kill_status.set("请先启动，并进入有敌方角色的战斗。")
                return
            manager = read_u32(self.handle, self.base + MANAGER_PTR)
            ok, actors = list_actors(self.handle, manager) if manager else (False, [])
            if not ok:
                self.kill_status.set("请先启动，并进入有敌方角色的战斗。")
                return
            self.kill_queue.clear()
            self.kill_next = self.kill_done = self.kill_skipped = 0
            self.kill_cancel = False
            now = now_ms()
            for a in actors:
                if self.poison_var.get() and self.poison_due(a, now):
                    k = make_kill(self.handle, self.base, self.actor, a, True)
                    if k:
                        self.kill_queue.append((a, True))
                if self.kill_var.get():
                    k = make_kill(self.handle, self.base, self.actor, a, False)
                    if k:
                        self.kill_queue.append((a, False))
            if not self.kill_queue:
                self.kill_status.set("已勾选，等待可操作目标；NPC 中毒间隔 4 秒补一次。")
                return
            self.kill_status.set("正在执行；上一轮未结束时不重复创建任务。")
            self.poll_kill()

        def auto_tick(self):
            self.poll_kill()
            wanted = self.kill_var.get() or self.poison_var.get()
            if round_due(now_ms(), self.last_round, self.kill_busy(),
                         self.auto_fault or self.disconnect_pending, wanted):
                self.last_round = now_ms()
                self.start_kill()

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


def main():
    if os.name != "nt":
        print("请在 Windows 上运行本脚本（需要读写游戏进程内存）。")
        return 1
    if "--self-test" in sys.argv:
        return self_test()
    if "--list" in sys.argv:
        return list_processes()
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
