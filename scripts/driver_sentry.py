import ctypes
from ctypes import wintypes
import sys
import os

psapi = ctypes.WinDLL('psapi.dll')
kernel32 = ctypes.WinDLL('kernel32.dll')

EnumDeviceDrivers = psapi.EnumDeviceDrivers
EnumDeviceDrivers.restype = wintypes.BOOL
EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

GetDeviceDriverBaseNameW = psapi.GetDeviceDriverBaseNameW
GetDeviceDriverBaseNameW.restype = wintypes.DWORD
GetDeviceDriverBaseNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]

def get_loaded_drivers():
    cb_needed = wintypes.DWORD()
    EnumDeviceDrivers(None, 0, ctypes.byref(cb_needed))
    
    count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
    drivers_array = (ctypes.c_void_p * count)()
    
    drivers = []
    if EnumDeviceDrivers(drivers_array, cb_needed.value, ctypes.byref(cb_needed)):
        actual_count = cb_needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(actual_count):
            base_addr = drivers_array[i]
            name_buf = ctypes.create_unicode_buffer(512)
            if GetDeviceDriverBaseNameW(base_addr, name_buf, 512):
                drivers.append({
                    "name": name_buf.value,
                    "address": hex(base_addr if base_addr else 0)
                })
    return drivers

def audit_vulnerable_drivers(drivers):
    # Known BYOVD (Bring Your Own Vulnerable Driver) list signatures
    flagged = {"gdrv.sys", "mhyprot2.sys", "procexp.sys", "dbutil_2_3.sys", "rtcore64.sys", "eneio64.sys"}
    findings = []
    for d in drivers:
        if d["name"].lower() in flagged:
            findings.append(d)
    return findings

if __name__ == '__main__':
    print("[Driver-Sentry] Windows Kernel Driver Enumerator & BYOVD Auditor")
    loaded = get_loaded_drivers()
    print(f"Total active kernel drivers enumerated: {len(loaded)}")
    
    suspicious = audit_vulnerable_drivers(loaded)
    if suspicious:
        print(f"\n[ALERT] Found {len(suspicious)} known high-risk driver(s):")
        for s in suspicious:
            print(f" - {s['name']} at {s['address']}")
    else:
        print("Audit clean: No known vulnerable/exploit drivers currently loaded.")
    
    print("\nSample of loaded kernel modules:")
    for d in loaded[:10]:
        print(f"  {d['address']:<20} {d['name']}")
