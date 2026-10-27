#!/usr/bin/env python3
"""Test-only TPM command bridge over stdin/stdout; no network sockets required.

Requires libtpms.so.0 (libtpms0 on Debian/Ubuntu). Never use with production secrets.
Set LIBTPMS_PATH to an absolute shared-library path if it is not installed globally.
"""
import ctypes as c
import os
import struct
import sys

lib = c.CDLL(os.environ.get("LIBTPMS_PATH", "libtpms.so.0"))
lib.TPMLIB_ChooseTPMVersion.argtypes = [c.c_int]
lib.TPMLIB_ChooseTPMVersion.restype = c.c_uint32
lib.TPMLIB_MainInit.restype = c.c_uint32
lib.TPMLIB_Process.argtypes = [c.POINTER(c.c_void_p), c.POINTER(c.c_uint32),
                              c.POINTER(c.c_uint32), c.c_void_p, c.c_uint32]
lib.TPMLIB_Process.restype = c.c_uint32
lib.TPMLIB_Terminate.restype = None
lib.TPMLIB_GetState.argtypes = [c.c_int, c.POINTER(c.c_void_p), c.POINTER(c.c_uint32)]
lib.TPMLIB_GetState.restype = c.c_uint32
lib.TPMLIB_SetState.argtypes = [c.c_int, c.c_void_p, c.c_uint32]
lib.TPMLIB_SetState.restype = c.c_uint32
libc = c.CDLL(None)
libc.free.argtypes = [c.c_void_p]

def read_exact(n):
    out = b""
    while len(out) < n:
        chunk = sys.stdin.buffer.read(n - len(out))
        if not chunk:
            raise EOFError
        out += chunk
    return out

assert lib.TPMLIB_ChooseTPMVersion(1) == 0
assert lib.TPMLIB_MainInit() == 0
try:
    while True:
        header = read_exact(10)
        size = struct.unpack(">I", header[2:6])[0]
        if not 10 <= size <= 8192:
            raise ValueError("invalid command length")
        command = header + read_exact(size - 10)
        # Test-only power-cycle control, not a TPM command. Preserve permanent state,
        # discard volatile state, and require a fresh TPM2_Startup(CLEAR).
        if command[6:10] == b"\xff\xff\xff\xff":
            permanent, plen = c.c_void_p(), c.c_uint32()
            assert lib.TPMLIB_GetState(1, c.byref(permanent), c.byref(plen)) == 0
            try:
                lib.TPMLIB_Terminate()
                assert lib.TPMLIB_SetState(1, permanent, plen.value) == 0
                assert lib.TPMLIB_MainInit() == 0
            finally:
                libc.free(permanent)
            sys.stdout.buffer.write(bytes.fromhex("80010000000a00000000"))
            sys.stdout.buffer.flush()
            continue
        data = c.create_string_buffer(command)
        response, length, allocated = c.c_void_p(), c.c_uint32(), c.c_uint32()
        rc = lib.TPMLIB_Process(c.byref(response), c.byref(length),
                                c.byref(allocated), data, len(command))
        if rc:
            raise RuntimeError(f"libtpms error {rc:#x}")
        try:
            reply = c.string_at(response, length.value)
            if os.environ.get("TPMBOOT_TEST_TRACE"):
                print(f"TPM command={command[6:10].hex()} rc={reply[6:10].hex()}", file=sys.stderr)
            sys.stdout.buffer.write(reply)
            sys.stdout.buffer.flush()
        finally:
            libc.free(response)
except EOFError:
    pass
finally:
    lib.TPMLIB_Terminate()
