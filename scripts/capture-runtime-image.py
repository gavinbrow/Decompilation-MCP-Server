"""Read the normally running game's .text into a private local PE copy.

Reads only. Never writes process memory or modifies the installed executable.
Requires the loaded module's preferred base, keeping checker addresses canonical.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import struct

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
SIZE_T = ctypes.c_size_t

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('th32ModuleID', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD), ('GlblcntUsage', wintypes.DWORD),
                ('ProccntUsage', wintypes.DWORD), ('modBaseAddr', ctypes.POINTER(ctypes.c_ubyte)),
                ('modBaseSize', wintypes.DWORD), ('hModule', wintypes.HMODULE),
                ('szModule', wintypes.WCHAR * 256), ('szExePath', wintypes.WCHAR * 260)]

kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, SIZE_T, ctypes.POINTER(SIZE_T)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def module_base(pid, original):
    snapshot = kernel32.CreateToolhelp32Snapshot(0x08 | 0x10, pid)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        row = MODULEENTRY32W()
        row.dwSize = ctypes.sizeof(row)
        found = kernel32.Module32FirstW(snapshot, ctypes.byref(row))
        while found:
            if Path(row.szExePath).resolve() == original.resolve():
                return ctypes.cast(row.modBaseAddr, ctypes.c_void_p).value
            found = kernel32.Module32NextW(snapshot, ctypes.byref(row))
        raise RuntimeError('Original game module was not found in the selected process')
    finally:
        kernel32.CloseHandle(snapshot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--settings', type=Path, default=Path('local/settings.json'))
    parser.add_argument('--output', type=Path, default=Path('work/worker1/FalloutNV.runtime-text.exe'))
    args = parser.parse_args()
    original = Path(json.loads(args.settings.read_text())['game_exe'])
    if args.output.resolve() == original.resolve():
        raise RuntimeError('Output must never be the original executable')
    data = bytearray(original.read_bytes())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    count = struct.unpack_from('<H', data, pe + 6)[0]
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    preferred_base = struct.unpack_from('<I', data, optional + 28)[0]
    base = module_base(args.pid, original)
    if base != preferred_base:
        raise RuntimeError('Loaded module is relocated; declining to reconstruct a noncanonical checker image')
    sections = []
    for i in range(count):
        section = optional + optional_size + i * 40
        name, virtual_size, rva, raw_size, raw = struct.unpack_from('<8sIIII', data, section)
        if name.rstrip(b'\0') == b'.text':
            sections.append((rva, min(raw_size, virtual_size), raw))
    if len(sections) != 1:
        raise RuntimeError('Expected exactly one .text section')
    process = kernel32.OpenProcess(0x0010 | 0x1000, False, args.pid)
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        for rva, length, raw in sections:
            # Read page-sized chunks so any inaccessible page produces a precise error.
            for offset in range(0, length, 0x1000):
                size = min(0x1000, length - offset)
                buffer = ctypes.create_string_buffer(size)
                copied = SIZE_T()
                if not kernel32.ReadProcessMemory(process, base + rva + offset, buffer, size, ctypes.byref(copied)):
                    raise ctypes.WinError(ctypes.get_last_error())
                if copied.value != size:
                    raise RuntimeError('Incomplete process-memory read')
                data[raw + offset:raw + offset + size] = buffer.raw
    finally:
        kernel32.CloseHandle(process)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print('Saved private runtime .text image:', args.output.resolve())
    print('Original installed executable unchanged. Do not publish this private image.')

if __name__ == '__main__':
    main()
