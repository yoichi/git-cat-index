#!/usr/bin/env python
import hashlib
import sys


def get_integer(buf, index, size):
    value = 0
    while size > 0:
        value <<= 8
        value += ord(buf[index])
        index += 1
        size -= 1
    return value


def parse_header(data, ptr, metadata):
    """Parse 12-byte header and checksum"""
    # 4-byte signature stands for "dircache"
    sig = data[ptr:ptr+4]
    if sig != "DIRC":
        print("%s is not a index file" % sys.argv[1])
        sys.exit(-1)
    ptr += 4

    # 4-byte version number
    version = get_integer(data, ptr, 4)
    if version not in (2, 3, 4):
        print("unsupported version number %d", version)
        sys.exit(-1)
    metadata["version"] = version
    ptr += 4

    # 32-bit number of index entries
    metadata["number"] = get_integer(data, ptr, 4)
    ptr += 4

    size = len(data)
    if size < ptr + 20:
        print("data is too short")
        sys.exit(-1)

    sha1 = hashlib.sha1(data[:-20]).digest()
    if sha1 != data[-20:]:
        print("checksum mismatch")
        sys.exit(-1)
    metadata["endptr"] = size - 20

    metadata["msgs"].append(
        "%s (dircache), %d entries" % (sig, metadata["number"]))
    return ptr


def parse_entry(data, ptr, metadata):
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
    ptr += 4
    # uid
    ptr += 4
    # gid
    ptr += 4
    # file size
    ptr += 4
    # SHA-1 hash of blob object
    sha1 = "".join(format(ord(x), '02x') for x in data[ptr:ptr+20])
    ptr += 20
    # flags
    flags = get_integer(data, ptr, 2)
    stage = (flags >> 12) & 0x3
    ptr += 2
    if metadata["version"] == 2:
        assert (flags & 0x4000) == 0
    elif flags & 0x4000:
        ptr += 2
    name_length = flags & 0xFFF
    if name_length < 0xFFF:
        metadata["msgs"].append(
            "%s (stage:%d) %s" % (sha1, stage, data[ptr:ptr+name_length]))
        ptr += name_length
    else:
        name_end = data.find("\0", ptr)
        assert name_end != -1
        metadata["msgs"].append(
            "%s (stage:%d) %s" % (sha1, stage, data[ptr:name_end]))
        ptr = name_end

    if metadata["version"] != 4:
        # 1-8 nul bytes
        ptr += 8 - (ptr - entry_begin) % 8
    return ptr


def parse_ext_tree(data, ptr, size, metadata):
    """Parse payload of cached tree extension"""
    end = ptr+size
    while ptr < end:
        path_end = data.find("\0", ptr, end)
        assert path_end != -1
        path = data[ptr:path_end]
        ptr = path_end+1

        entry_count_end = data.find(" ", ptr, end)
        assert entry_count_end != -1
        entry_count = data[ptr:entry_count_end]
        ptr = entry_count_end+1

        subtrees_end = data.find("\n", ptr, end)
        assert subtrees_end != 1
        subtrees = data[ptr:subtrees_end]
        ptr = subtrees_end+1

        if entry_count[0] == "-":
            metadata["msgs"].append(
                "invalidated (%s/%s) %s" % (subtrees, entry_count, path))
        else:
            assert ptr+20 <= end
            sha1 = "".join(format(ord(x), '02x') for x in data[ptr:ptr+20])
            metadata["msgs"].append(
                "%s (%s/%s) %s" % (sha1, subtrees, entry_count, path))
            ptr += 20


def parse_ext_reuc(data, ptr, size, metadata):
    """Parse payload of resolve undo extension"""
    end = ptr+size
    while ptr < end:
        path_end = data.find("\0", ptr, end)
        assert path_end != -1
        path = data[ptr:path_end]
        ptr = path_end+1

        modes = []

        mode1_end = data.find("\0", ptr, end)
        assert mode1_end != -1
        modes.append(data[ptr:mode1_end])
        ptr = mode1_end+1
        
        mode2_end = data.find("\0", ptr, end)
        assert mode2_end != -1
        modes.append(data[ptr:mode2_end])
        ptr = mode2_end+1

        mode3_end = data.find("\0", ptr, end)
        assert mode3_end != -1
        modes.append(data[ptr:mode3_end])
        ptr = mode3_end+1

        for i in range(3):
            if modes[i] == "0":
                metadata["msgs"].append(
                    "%40s (stage:%d) %6s %s" % ("", i+1, modes[i], path))
            else:
                assert ptr+20 <= end
                sha1 = "".join(format(ord(x), '02x') for x in data[ptr:ptr+20])
                metadata["msgs"].append(
                    "%s (stage:%d) %6s %s" % (sha1, i+1, modes[i], path))
                ptr += 20

    pass


def parse_ext_link(data, ptr, size, metadata):
    """Parse payload of split index extension"""
    pass


def parse_extension(data, ptr, metadata):
    sig = data[ptr:ptr+4]
    ptr += 4

    size = get_integer(data, ptr, 4)
    ptr += 4

    metadata["msgs"].append(sig)
    if sig == "TREE":
        parse_ext_tree(data, ptr, size, metadata)
    elif sig == "REUC":
        parse_ext_reuc(data, ptr, size, metadata)
    elif sig == "link":
        parse_ext_link(data, ptr, size, metadata)
    else:
        raise Exception("unknown signature %s" % sig)

    return ptr + size


# https://www.kernel.org/pub/software/scm/git/docs/technical/index-format.txt
def parse(fname):
    try:
        f = open(fname)
    except Exception:
        print("open %s failed" % sys.argv[1])
        sys.exit(-1)

    data = f.read()

    metadata = {"msgs": []}
    ptr = 0

    ptr = parse_header(data, ptr, metadata)

    while ptr < metadata["endptr"]:
        if metadata["number"] > 0:
            ptr = parse_entry(data, ptr, metadata)
            metadata["number"] -= 1
        else:
            ptr = parse_extension(data, ptr, metadata)
    return metadata["msgs"]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: %s index_file" % sys.argv[0])
        sys.exit(-1)
    msgs = parse(sys.argv[1])
    for msg in msgs:
        print(msg)
