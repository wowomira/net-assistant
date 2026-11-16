"""Minimal native Windows SCM bridge. No scheduling rules live in this adapter."""
import ctypes
from ctypes import wintypes
import os
import threading


class ChildJob:
    """Kill scan descendants if the scheduler process exits, including crashes."""
    def __enter__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel.CloseHandle(self.handle)
            raise error
        return self

    def assign(self, pid):
        handle = self.kernel.OpenProcess(0x0100 | 0x0001, False, pid)  # SET_QUOTA | TERMINATE
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel.CloseHandle(handle)

    def terminate(self):
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def __exit__(self, *_):
        self.kernel.CloseHandle(self.handle)


def serve(name, config, *, runner=None):
    if os.name != "nt":
        raise RuntimeError("Windows service adapter requires Windows.")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    service_main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    handler_type = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, ctypes.c_void_p)

    class Status(ctypes.Structure):
        _fields_ = [(field, wintypes.DWORD) for field in (
            "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
            "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint")]

    class Entry(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", service_main_type)]

    advapi.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_type, ctypes.c_void_p]
    advapi.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(Status)]
    advapi.SetServiceStatus.restype = wintypes.BOOL
    advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]
    advapi.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    stop = threading.Event()
    handle = None
    current = Status()
    status_lock = threading.RLock()

    def report(state, *, code=0):
        nonlocal current
        with status_lock:
            current = Status(0x10, state, 0x01 | 0x04 if state == 4 else 0,
                             1066 if code else 0, code, 1 if state in (2, 3) else 0,
                             20000 if state in (2, 3) else 0)
            if not advapi.SetServiceStatus(handle, ctypes.byref(current)):
                raise ctypes.WinError(ctypes.get_last_error())

    @handler_type
    def handler(control, _event_type, _event_data, _context):
        if control in (1, 5):  # STOP, SHUTDOWN
            report(3)
            stop.set()
        elif control == 4:  # INTERROGATE
            with status_lock:
                advapi.SetServiceStatus(handle, ctypes.byref(current))
        return 0

    @service_main_type
    def service_main(_argc, _argv):
        nonlocal handle
        handle = advapi.RegisterServiceCtrlHandlerExW(name, handler, None)
        if not handle:
            return
        code = 1
        try:
            report(2)
            if runner is None:
                from app.scheduling.worker import run_worker
            else:
                run_worker = runner
            report(4)
            code = run_worker(config, stop_event=stop)
        except BaseException:
            code = 1
        finally:
            report(1, code=code)

    table = (Entry * 2)()
    table[0] = Entry(name, service_main)
    # Keep callbacks/table alive until SCM ends ServiceMain.
    if not advapi.StartServiceCtrlDispatcherW(table):
        raise ctypes.WinError(ctypes.get_last_error())
