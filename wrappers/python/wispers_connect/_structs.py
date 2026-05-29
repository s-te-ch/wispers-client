"""ctypes Structure subclasses matching C structs in wispers_connect.h."""

from __future__ import annotations

from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    c_char_p,
    c_int,
    c_int32,
    c_size_t,
    c_uint8,
    c_void_p,
)

# ---------------------------------------------------------------------------
# Storage callback function-pointer types
# ---------------------------------------------------------------------------

LoadRootKeyFunc = CFUNCTYPE(c_int, c_void_p, POINTER(c_uint8), c_size_t)
SaveRootKeyFunc = CFUNCTYPE(c_int, c_void_p, POINTER(c_uint8), c_size_t)
DeleteRootKeyFunc = CFUNCTYPE(c_int, c_void_p)

LoadRegistrationFunc = CFUNCTYPE(c_int, c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_size_t))
SaveRegistrationFunc = CFUNCTYPE(c_int, c_void_p, POINTER(c_uint8), c_size_t)
DeleteRegistrationFunc = CFUNCTYPE(c_int, c_void_p)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

class WispersNodeStorageCallbacks(Structure):
    _fields_ = [
        ("ctx", c_void_p),
        ("load_root_key", LoadRootKeyFunc),
        ("save_root_key", SaveRootKeyFunc),
        ("delete_root_key", DeleteRootKeyFunc),
        ("load_registration", LoadRegistrationFunc),
        ("save_registration", SaveRegistrationFunc),
        ("delete_registration", DeleteRegistrationFunc),
    ]


class WispersRegistrationInfo(Structure):
    _fields_ = [
        ("connectivity_group_id", c_char_p),
        ("node_number", c_int32),
        ("auth_token", c_char_p),
        ("attestation_jwt", c_char_p),
    ]
