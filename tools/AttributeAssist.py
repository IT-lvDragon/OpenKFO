#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""属性助手（单机版）—— 游戏运行后可选启动的属性修改脚本。

原理与 tools/game-mod/main.cpp 一致：外部进程读写（ReadProcessMemory /
WriteProcessMemory），不注入 DLL、不修改任何游戏文件。取消勾选、停止或
游戏退出时，尽量恢复启用前的原始值。

用法：
  python AttributeAssist.py           打开界面：选择游戏进程 → 点击“启动”
  python AttributeAssist.py --self-test  无界面自检（校验角色定位与恢复逻辑）

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

# 功能表：use_state=True 时偏移基于 state 指针，否则基于 actor 指针。
# is_int=True 为开关型（固定写 1）；否则按 0–999 浮点写入。
FEATURES = [
    dict(name="怒气倍率（999≈无限怒气）", offset=0x80, use_state=True, is_int=False, initial="999", scale=1.0),
    dict(name="无敌", offset=0x1780, use_state=True, is_int=True, initial="1"),
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
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
k32.GetCurrentProcess.restype = wintypes.HANDLE


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_ssize_t),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


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
def find_processes():
    out = []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) or 0
    if not snap or snap == INVALID_HANDLE:
        return out
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if k32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                name = entry.szExeFile
                if name.lower() in GAME_NAMES:
                    out.append((entry.th32ProcessID, name))
                if not k32.Process32NextW(snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snap)
    return out


def module_base(pid):
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) or 0
    if not snap or snap == INVALID_HANDLE:
        return 0
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    base = 0
    if k32.Module32FirstW(snap, ctypes.byref(entry)) and entry.modBaseAddr:
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

        def save_settings(self):
            path = settings_path()
            if not path:
                return
            data = {"features": [{"enabled": self.rows[i][0].get(),
                                  "value": self.rows[i][1].get()}
                                 for i in range(len(self.features))]}
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
            found = find_processes()
            if [pid for pid, _name in found] == self.pids:
                return
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
            self.root.after(1000, self.refresh)

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
            self.status.set("已启动。沿用勾选设置，换局自动继续，无需重复连接。")

        def stop_clicked(self):
            self.stop()

        def stop(self, silent=False):
            if not self.handle:
                if not silent:
                    self.status.set("尚未连接游戏进程。")
                return True
            if k32.WaitForSingleObject(self.handle, 0) == WAIT_OBJECT_0:
                self.actor = None  # 游戏已退出，原值无法也无需恢复
            if not self.restore_all():
                self.status.set("恢复原值失败，请保持游戏运行后重试停止。")
                return False
            k32.CloseHandle(self.handle)
            self.handle, self.base, self.actor = 0, 0, None
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
                    self.restore_all()
                    k32.CloseHandle(self.handle)
                    self.handle, self.base, self.actor = 0, 0, None
                    for _enabled, _entry, value in self.rows:
                        value.set("—")
                    self.status.set("游戏进程已退出，已停止操作；勾选保留。选择新进程后点击启动。")
                else:
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
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
