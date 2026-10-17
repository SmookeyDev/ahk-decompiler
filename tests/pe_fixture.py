"""Tiny non-executable PE fixtures constructed from our own bytes."""

import struct


def make_pe(script=None, *, virtual=False, machine=0x14C, name=">AUTOHOTKEY SCRIPT<", language=1033):
    resource = bytearray(128)
    if script is not None:
        struct.pack_into("<HHII", resource, 12, 0, 1, 10, 0x80000018)
        struct.pack_into("<HHII", resource, 36, 1, 0, 0x80000058, 0x80000030)
        struct.pack_into("<HHII", resource, 60, 0, 1, language, 72)
        encoded_name = name.encode("utf-16-le")
        resource[88 : 88 + len(encoded_name) + 2] = struct.pack("<H", len(name)) + encoded_name
        data_offset = (90 + len(encoded_name) + 3) & ~3
        resource.extend(b"\0" * max(0, data_offset - len(resource)))
        data_rva = 0x4000 if virtual else 0x1000 + data_offset
        struct.pack_into("<IIII", resource, 72, data_rva, len(script), 1252, 0)
        if not virtual:
            resource[data_offset : data_offset + len(script)] = script
    optional_size = 240 if machine == 0x8664 else 224
    header = bytearray(512)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, machine, 1, 0, 0, 0, optional_size, 0x102)
    optional = 0x98
    struct.pack_into("<H", header, optional, 0x20B if machine == 0x8664 else 0x10B)
    struct.pack_into("<I", header, optional + 32, 0x1000)
    struct.pack_into("<I", header, optional + 36, 0x200)
    struct.pack_into("<I", header, optional + 56, 0x6000)
    struct.pack_into("<I", header, optional + 60, 512)
    directory = optional + (112 if machine == 0x8664 else 96)
    struct.pack_into("<I", header, directory - 4, 16)
    if script is not None:
        struct.pack_into("<II", header, directory + 16, 0x1000, len(resource))
    raw_size = (len(resource) + 511) & ~511
    section = optional + optional_size
    header[section : section + 8] = b".oddname"
    struct.pack_into(
        "<IIII", header, section + 8, 0x5000 if virtual else len(resource), 0x1000, raw_size, 512
    )
    struct.pack_into("<I", header, section + 36, 0x40000040)
    return bytes(header) + bytes(resource).ljust(raw_size, b"\0")
