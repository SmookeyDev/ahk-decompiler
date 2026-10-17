"""Process identity and ownership. Owned Windows trees live in a private Job Object."""

from __future__ import annotations

import ctypes as ct
import subprocess
import sys
from dataclasses import dataclass

import psutil

from .winapi import DWORD, HANDLE, SIZE_T, WORD, WindowsAPI, WindowsAPIError, bind


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    name: str = ""

    @classmethod
    def capture(cls, pid):
        process = psutil.Process(pid)
        return cls(pid, process.create_time(), process.name())

    def alive(self):
        try:
            process = psutil.Process(self.pid)
            return (
                abs(process.create_time() - self.create_time) < 0.00001
                and process.is_running()
                and process.status() != psutil.STATUS_ZOMBIE
            )
        except psutil.Error:
            return False


class _StartupInfo(ct.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("reserved", ct.c_wchar_p),
        ("desktop", ct.c_wchar_p),
        ("title", ct.c_wchar_p),
        ("x", DWORD),
        ("y", DWORD),
        ("xsize", DWORD),
        ("ysize", DWORD),
        ("xchars", DWORD),
        ("ychars", DWORD),
        ("fill", DWORD),
        ("flags", DWORD),
        ("show", WORD),
        ("reserved_size", WORD),
        ("reserved_data", HANDLE),
        ("stdin", HANDLE),
        ("stdout", HANDLE),
        ("stderr", HANDLE),
    ]


class _ProcessInfo(ct.Structure):
    _fields_ = [("process", HANDLE), ("thread", HANDLE), ("pid", DWORD), ("tid", DWORD)]


class _BasicLimits(ct.Structure):
    _fields_ = [
        ("process_time", ct.c_int64),
        ("job_time", ct.c_int64),
        ("flags", DWORD),
        ("min_working_set", SIZE_T),
        ("max_working_set", SIZE_T),
        ("active_limit", DWORD),
        ("affinity", SIZE_T),
        ("priority", DWORD),
        ("scheduling", DWORD),
    ]


class _IOCounters(ct.Structure):
    _fields_ = [
        (name, ct.c_uint64)
        for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")
    ]


class _ExtendedLimits(ct.Structure):
    _fields_ = [
        ("basic", _BasicLimits),
        ("io", _IOCounters),
        ("process_memory", SIZE_T),
        ("job_memory", SIZE_T),
        ("peak_process_memory", SIZE_T),
        ("peak_job_memory", SIZE_T),
    ]


class WindowsJob:
    def __init__(self, target, arguments=()):
        self.api = WindowsAPI()
        kernel = self.api.kernel
        self.job = self.process = self.thread = None
        create_job = bind(kernel, "CreateJobObjectW", HANDLE, [HANDLE, ct.c_wchar_p])
        set_info = bind(kernel, "SetInformationJobObject", ct.c_int, [HANDLE, ct.c_int, HANDLE, DWORD])
        create = bind(
            kernel,
            "CreateProcessW",
            ct.c_int,
            [
                ct.c_wchar_p,
                ct.c_wchar_p,
                HANDLE,
                HANDLE,
                ct.c_int,
                DWORD,
                HANDLE,
                ct.c_wchar_p,
                ct.POINTER(_StartupInfo),
                ct.POINTER(_ProcessInfo),
            ],
        )
        assign = bind(kernel, "AssignProcessToJobObject", ct.c_int, [HANDLE, HANDLE])
        resume = bind(kernel, "ResumeThread", DWORD, [HANDLE])
        self.terminate = bind(kernel, "TerminateProcess", ct.c_int, [HANDLE, ct.c_uint])
        self.wait = bind(kernel, "WaitForSingleObject", DWORD, [HANDLE, DWORD])
        self.query = bind(
            kernel, "QueryInformationJobObject", ct.c_int, [HANDLE, ct.c_int, HANDLE, DWORD, HANDLE]
        )
        self.terminate_job = bind(kernel, "TerminateJobObject", ct.c_int, [HANDLE, ct.c_uint])
        try:
            self.job = create_job(None, None)
            if not self.job:
                raise WindowsAPIError("CreateJobObjectW", ct.get_last_error())
            limits = _ExtendedLimits()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not set_info(self.job, 9, ct.byref(limits), ct.sizeof(limits)):
                raise WindowsAPIError("SetInformationJobObject", ct.get_last_error())
            startup, info = _StartupInfo(), _ProcessInfo()
            startup.cb = ct.sizeof(startup)
            command = ct.create_unicode_buffer(subprocess.list2cmdline([str(target), *arguments]))
            if not create(
                str(target),
                command,
                None,
                None,
                False,
                0x4,
                None,
                str(target.parent),
                ct.byref(startup),
                ct.byref(info),
            ):
                raise WindowsAPIError("CreateProcessW", ct.get_last_error())
            self.process, self.thread, self.pid = info.process, info.thread, info.pid
            if not assign(self.job, self.process):
                # Never run an unowned process if tree ownership could not be established.
                self.terminate(self.process, 1)
                raise WindowsAPIError("AssignProcessToJobObject", ct.get_last_error())
            self.identity = ProcessIdentity.capture(self.pid)
            if resume(self.thread) == 0xFFFFFFFF:
                raise WindowsAPIError("ResumeThread", ct.get_last_error())
            self.api.close(self.thread)
            self.thread = None
        except BaseException:
            self.close()
            raise

    def pids(self):
        buffer = ct.create_string_buffer(1024 * 1024)
        if not self.query(self.job, 3, buffer, ct.sizeof(buffer), None):
            raise WindowsAPIError("QueryInformationJobObject", ct.get_last_error())
        count = DWORD.from_buffer(buffer, 4).value
        capacity = (len(buffer) - 8) // ct.sizeof(SIZE_T)
        if count > capacity:
            raise ValueError("Job Object process list exceeds the configured bound")
        return [SIZE_T.from_buffer(buffer, 8 + index * ct.sizeof(SIZE_T)).value for index in range(count)]

    def close(self):
        if self.job:
            self.terminate_job(self.job, 0)
        if self.process:
            self.wait(self.process, 5000)
        for name in ("thread", "process", "job"):
            handle = getattr(self, name, None)
            if handle:
                self.api.close(handle)
                setattr(self, name, None)


class ProcessSession:
    def __init__(self, config):
        self.job = None
        self.owned = config.pid is None
        self.monitor_children = config.monitor_children
        if self.owned:
            if not config.allow_execution:
                raise PermissionError("Dynamic extraction requires explicit execution permission")
            self.job = WindowsJob(config.target, config.arguments)
            self.root = self.job.identity
        else:
            self.root = ProcessIdentity.capture(config.pid)
            if sys.platform != "win32":
                from .winapi import UnsupportedPlatformError

                raise UnsupportedPlatformError("Process memory extraction requires Windows")
        self.known = {self.root.pid: self.root}

    def discover(self):
        if self.job and self.monitor_children:
            pids = self.job.pids()
        elif self.monitor_children:
            pids = []
            for identity in list(self.known.values()):
                if identity.alive():
                    try:
                        process = psutil.Process(identity.pid)
                        if abs(process.create_time() - identity.create_time) < 0.00001:
                            pids.extend(child.pid for child in process.children(recursive=True))
                    except psutil.Error:
                        continue
        else:
            pids = []
        for pid in pids:
            if pid not in self.known or not self.known[pid].alive():
                try:
                    self.known[pid] = ProcessIdentity.capture(pid)
                except psutil.Error:
                    continue
        return list(self.known.values())

    def close(self):
        if self.job:
            self.job.close()
