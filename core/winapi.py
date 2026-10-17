"""Typed Windows API boundary. Importing it is portable; initialization is not."""

from __future__ import annotations

import ctypes as ct
import sys
from dataclasses import dataclass

DWORD = ct.c_uint32
WORD = ct.c_uint16
HANDLE = ct.c_void_p
SIZE_T = ct.c_size_t
PROCESS_READ_ACCESS = 0x0400 | 0x0010


class UnsupportedPlatformError(RuntimeError):
    pass


class UnsupportedArchitectureError(RuntimeError):
    pass


class WindowsAPIError(OSError):
    def __init__(self, operation: str, code: int):
        self.operation = operation
        message = ct.FormatError(code).strip() if sys.platform == "win32" else f"Windows error {code}"
        super().__init__(code, f"{operation}: {message}")
        self.winerror = code


class MEMORY_BASIC_INFORMATION32(ct.Structure):
    _fields_ = [
        (name, DWORD)
        for name in (
            "BaseAddress",
            "AllocationBase",
            "AllocationProtect",
            "RegionSize",
            "State",
            "Protect",
            "Type",
        )
    ]


class MEMORY_BASIC_INFORMATION64(ct.Structure):
    _fields_ = [
        ("BaseAddress", ct.c_uint64),
        ("AllocationBase", ct.c_uint64),
        ("AllocationProtect", DWORD),
        ("_alignment1", DWORD),
        ("RegionSize", ct.c_uint64),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("_alignment2", DWORD),
    ]


MEMORY_BASIC_INFORMATION = (
    MEMORY_BASIC_INFORMATION64 if ct.sizeof(HANDLE) == 8 else MEMORY_BASIC_INFORMATION32
)


@dataclass(frozen=True)
class MemoryRegion:
    base: int
    size: int
    state: int
    protection: int
    allocation_base: int = 0
    type: int = 0


class _SystemInfo(ct.Structure):
    _fields_ = [
        ("architecture", DWORD),
        ("page_size", DWORD),
        ("minimum", HANDLE),
        ("maximum", HANDLE),
        ("mask", SIZE_T),
        ("processors", DWORD),
        ("processor_type", DWORD),
        ("granularity", DWORD),
        ("level", WORD),
        ("revision", WORD),
    ]


@dataclass(frozen=True)
class ReadResult:
    data: bytes
    error: int = 0


def bind(library, name, restype, argtypes):
    function = getattr(library, name)
    function.restype = restype
    function.argtypes = argtypes
    return function


class WindowsAPI:
    def __init__(self):
        if sys.platform != "win32":
            raise UnsupportedPlatformError("Process memory extraction requires Windows")
        self.kernel = ct.WinDLL("kernel32", use_last_error=True)
        info = _SystemInfo()
        bind(self.kernel, "GetSystemInfo", None, [ct.POINTER(_SystemInfo)])(ct.byref(info))
        self.maximum_address = int(info.maximum or 0)
        self.OpenProcess = bind(self.kernel, "OpenProcess", HANDLE, [DWORD, ct.c_int, DWORD])
        self.CloseHandle = bind(self.kernel, "CloseHandle", ct.c_int, [HANDLE])
        self.VirtualQueryEx = bind(
            self.kernel,
            "VirtualQueryEx",
            SIZE_T,
            [HANDLE, HANDLE, ct.POINTER(MEMORY_BASIC_INFORMATION), SIZE_T],
        )
        self.ReadProcessMemory = bind(
            self.kernel, "ReadProcessMemory", ct.c_int, [HANDLE, HANDLE, HANDLE, SIZE_T, ct.POINTER(SIZE_T)]
        )
        self.IsWow64Process2 = None
        if hasattr(self.kernel, "IsWow64Process2"):
            self.IsWow64Process2 = bind(
                self.kernel, "IsWow64Process2", ct.c_int, [HANDLE, ct.POINTER(WORD), ct.POINTER(WORD)]
            )
        self.IsWow64Process = bind(self.kernel, "IsWow64Process", ct.c_int, [HANDLE, ct.POINTER(ct.c_int)])
        self.GetCurrentProcess = bind(self.kernel, "GetCurrentProcess", HANDLE, [])
        self.EnumProcessModulesEx = bind(
            ct.WinDLL("psapi", use_last_error=True),
            "EnumProcessModulesEx",
            ct.c_int,
            [HANDLE, ct.POINTER(HANDLE), DWORD, ct.POINTER(DWORD), DWORD],
        )

    def open(self, pid: int):
        handle = self.OpenProcess(PROCESS_READ_ACCESS, False, pid)
        if not handle:
            raise WindowsAPIError("OpenProcess", ct.get_last_error())
        return handle

    def close(self, handle):
        if handle:
            self.CloseHandle(handle)

    def architecture(self, handle) -> str:
        if self.IsWow64Process2:
            process_machine, native_machine = WORD(), WORD()
            if not self.IsWow64Process2(handle, ct.byref(process_machine), ct.byref(native_machine)):
                raise WindowsAPIError("IsWow64Process2", ct.get_last_error())
            machine = process_machine.value or native_machine.value
            architecture = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, "unknown")
        else:
            target_wow, current_wow = ct.c_int(), ct.c_int()
            if not self.IsWow64Process(handle, ct.byref(target_wow)):
                raise WindowsAPIError("IsWow64Process", ct.get_last_error())
            if not self.IsWow64Process(self.GetCurrentProcess(), ct.byref(current_wow)):
                raise WindowsAPIError("IsWow64Process", ct.get_last_error())
            architecture = (
                "x86" if target_wow.value or (ct.sizeof(HANDLE) == 4 and not current_wow.value) else "x64"
            )
        if architecture == "unknown" or (architecture != "x86" and ct.sizeof(HANDLE) == 4):
            raise UnsupportedArchitectureError(
                f"A {ct.sizeof(HANDLE) * 8}-bit collector cannot read {architecture}"
            )
        return architecture

    def regions(self, handle):
        address = 0
        ceiling = min(
            self.maximum_address,
            0xFFFFFFFF if self.architecture(handle) == "x86" else (1 << (ct.sizeof(HANDLE) * 8)) - 1,
        )
        while address < ceiling:
            info = MEMORY_BASIC_INFORMATION()
            returned = self.VirtualQueryEx(handle, address, ct.byref(info), ct.sizeof(info))
            if not returned:
                error = ct.get_last_error()
                if error == 87 and address:
                    return  # End of the accessible address space.
                raise WindowsAPIError("VirtualQueryEx", error)
            if returned < ct.sizeof(info):
                raise WindowsAPIError("VirtualQueryEx (short structure)", 24)
            base, size = int(info.BaseAddress), int(info.RegionSize)
            following = base + size
            if size <= 0 or following <= address:
                raise ValueError("VirtualQueryEx returned a non-advancing region")
            yield MemoryRegion(base, size, info.State, info.Protect, info.AllocationBase, info.Type)
            address = following

    def read(self, handle, address: int, size: int) -> ReadResult:
        if size <= 0 or size > 4 * 1024 * 1024:
            raise ValueError("Each memory read must be between 1 byte and 4 MiB")
        buffer = ct.create_string_buffer(size)
        count = SIZE_T()
        ct.set_last_error(0)
        success = self.ReadProcessMemory(handle, address, buffer, size, ct.byref(count))
        error = 0 if success else ct.get_last_error()
        return ReadResult(buffer.raw[: min(count.value, size)], error)

    def module_base(self, handle) -> int:
        modules = (HANDLE * 1024)()
        needed = DWORD()
        if not self.EnumProcessModulesEx(handle, modules, ct.sizeof(modules), ct.byref(needed), 3):
            raise WindowsAPIError("EnumProcessModulesEx", ct.get_last_error())
        if not modules[0]:
            raise WindowsAPIError("EnumProcessModulesEx (empty)", 126)
        return int(modules[0])
