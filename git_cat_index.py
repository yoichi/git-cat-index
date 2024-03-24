#!/usr/bin/env python
"""Parse git index file"""


import hashlib
import sys


def _ord(x):
    if sys.version_info[0] < 3:
        return ord(x)
    else:
        return x


def _get_integer(buf, index, size):
    value = 0
    while size > 0:
        value <<= 8
        value += _ord(buf[index])
        index += 1
        size -= 1
    return value


def _parse_header(data, ptr, metadata, fname):
    """Parse 12-byte header and checksum"""
    # 4-byte signature stands for "dircache"
    sig = data[ptr:ptr+4]
    if sig != b"DIRC":
        raise Exception("%s is not a index file" % fname)
    ptr += 4

    # 4-byte version number
    version = _get_integer(data, ptr, 4)
    if version not in (2, 3, 4):
        raise Exception("unsupported version number %d", version)
    metadata["version"] = version
    ptr += 4

    # 32-bit number of index entries
    metadata["number"] = _get_integer(data, ptr, 4)
    ptr += 4

    size = len(data)
    if size < ptr + 20:
        raise Exception("data is too short")

    sha1 = hashlib.sha1(data[:-20]).digest()
    if sha1 != data[-20:]:
        raise Exception("checksum mismatch")
    metadata["endptr"] = size - 20

    metadata["msgs"].append(
        "%s (dircache), version %d, %d entries" % (sig.decode(), metadata["version"], metadata["number"]))
    return ptr


def _get_mode_str(m):
    return "%d%d0%d%d%d" % (
        m >> 15, (m >> 12) & 0x7,
        (m >> 6) & 0x7, (m >> 3) & 0x7, m & 0x7
    )


def _parse_entry(data, ptr, metadata):
    """Parse index entry"""
    entry_begin = ptr
    # ctime seconds
    ptr += 4
    # ctime nanosecond fractions
    ptr += 4
    # mtime seconds
    ptr += 4
    # mtime nanosecond fractions
    ptr += 4
    # dev
    ptr += 4
    # ino
    ptr += 4
    # mode
    mode = _get_mode_str(_get_integer(data, ptr, 4) & 0xFFFF)
    ptr += 4
    # uid
    ptr += 4
    # gid
    ptr += 4
    # file size
    ptr += 4
    # SHA-1 hash of blob object
    sha1 = "".join(format(_ord(x), '02x') for x in data[ptr:ptr+20])
    ptr += 20
    # flags
    flags = _get_integer(data, ptr, 2)
    # stage (during merge)
    stage = (flags >> 12) & 0x3
    ptr += 2
    extended = ""
    if metadata["version"] == 2:
        assert (flags & 0x4000) == 0
    elif flags & 0x4000:
        # extended flag
        extended_flag = _get_integer(data, ptr, 2)
        # skip-worktree flag (used by sparse checkout)
        if (extended_flag >> 14) & 0x1:
            extended += ",skip-worktree"
        # intent-to-add flag (used by "git add -N")
        if (extended_flag >> 13) & 0x1:
            extended += ",intent-to-add"
        ptr += 2
    if metadata["version"] == 4:
        offset = _get_integer(data, ptr, 1)
        ptr += 1
        name_end = data.find(b"\0", ptr)
        assert name_end != -1
        if offset == 0:
            name = metadata["name"]
        else:
            name = metadata["name"][:-offset]
        name += data[ptr:name_end].decode()
        metadata["msgs"].append(
            "%s (stage:%d%s) %6s %s" % (sha1, stage, extended, mode, name))
        metadata["name"] = name
        ptr = name_end + 1
    else:
        name_length = flags & 0xFFF
        if name_length < 0xFFF:
            metadata["msgs"].append(
                "%s (stage:%d%s) %6s %s" % (
                    sha1, stage, extended, mode,
                    data[ptr:ptr+name_length].decode()))
            ptr += name_length
        else:
            name_end = data.find(b"\0", ptr)
            assert name_end != -1
            metadata["msgs"].append(
                "%s (stage:%d%s) %6s %s" % (
                    sha1, stage, extended, mode, data[ptr:name_end].decode()))
            ptr = name_end

    if metadata["version"] != 4:
        # 1-8 nul bytes
        ptr += 8 - (ptr - entry_begin) % 8
    return ptr


def _parse_ext_tree(data, ptr, size, metadata):
    """Parse payload of cached tree extension"""
    end = ptr+size
    while ptr < end:
        path_end = data.find(b"\0", ptr, end)
        assert path_end != -1
        path = data[ptr:path_end]
        ptr = path_end+1

        entry_count_end = data.find(b" ", ptr, end)
        assert entry_count_end != -1
        entry_count = data[ptr:entry_count_end]
        ptr = entry_count_end+1

        subtrees_end = data.find(b"\n", ptr, end)
        assert subtrees_end != 1
        subtrees = data[ptr:subtrees_end]
        ptr = subtrees_end+1

        if entry_count[0] == b"-"[0]:
            metadata["msgs"].append(
                "invalidated (%s/%s) %s" % (
                    subtrees.decode(), entry_count.decode(),
                    path.decode()))
        else:
            assert ptr+20 <= end
            sha1 = "".join(format(_ord(x), '02x') for x in data[ptr:ptr+20])
            metadata["msgs"].append(
                "%s (%s/%s) %s" % (
                    sha1, subtrees.decode(), entry_count.decode(),
                    path.decode()))
            ptr += 20


def _parse_ext_reuc(data, ptr, size, metadata):
    """Parse payload of resolve undo extension"""
    end = ptr+size
    while ptr < end:
        path_end = data.find(b"\0", ptr, end)
        assert path_end != -1
        path = data[ptr:path_end]
        ptr = path_end+1

        modes = []

        mode1_end = data.find(b"\0", ptr, end)
        assert mode1_end != -1
        modes.append(data[ptr:mode1_end])
        ptr = mode1_end+1

        mode2_end = data.find(b"\0", ptr, end)
        assert mode2_end != -1
        modes.append(data[ptr:mode2_end])
        ptr = mode2_end+1

        mode3_end = data.find(b"\0", ptr, end)
        assert mode3_end != -1
        modes.append(data[ptr:mode3_end])
        ptr = mode3_end+1

        for i in range(3):
            if modes[i] == b"0":
                metadata["msgs"].append(
                    "%40s (stage:%d) %6s %s" % (
                        "", i+1, modes[i].decode(), path.decode()))
            else:
                assert ptr+20 <= end
                sha1 = "".join(format(_ord(x), '02x') for x in data[ptr:ptr+20])
                metadata["msgs"].append(
                    "%s (stage:%d) %6s %s" % (
                        sha1, i+1, modes[i].decode(), path.decode()))
                ptr += 20


def _parse_ext_link(data, ptr, size, metadata):
    """Parse payload of split index extension"""
    pass


def _parse_extension(data, ptr, metadata):
    sig = data[ptr:ptr+4]
    ptr += 4

    size = _get_integer(data, ptr, 4)
    ptr += 4

    metadata["msgs"].append(sig.decode())
    if sig == b"TREE":
        _parse_ext_tree(data, ptr, size, metadata)
    elif sig == b"REUC":
        _parse_ext_reuc(data, ptr, size, metadata)
    elif sig == b"link":
        _parse_ext_link(data, ptr, size, metadata)
    else:
        raise Exception("unknown signature %s" % sig)

    return ptr + size


# https://www.kernel.org/pub/software/scm/git/docs/technical/index-format.txt
def parse(fname):
    """Parse git index file"""
    with open(fname, "rb") as f:
        data = f.read()

    metadata = {"msgs": [], "name": ""}
    ptr = 0

    ptr = _parse_header(data, ptr, metadata, fname)

    while ptr < metadata["endptr"]:
        if metadata["number"] > 0:
            ptr = _parse_entry(data, ptr, metadata)
            metadata["number"] -= 1
        else:
            ptr = _parse_extension(data, ptr, metadata)
    return metadata["msgs"]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: %s index_file" % sys.argv[0])
        sys.exit(-1)
    msgs = parse(sys.argv[1])
    for msg in msgs:
        print(msg)
