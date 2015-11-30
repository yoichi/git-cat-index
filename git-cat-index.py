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
    if data[ptr:ptr+4] != "DIRC":
        print("%s is not a index file" % sys.argv[1])
        sys.exit(-1)
    ptr += 4

    version = get_integer(data, ptr, 4)
    if version not in (2, 3, 4):
        print("unsupported version number %d", version)
        sys.exit(-1)
    metadata["version"] = version
    ptr += 4

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

    return ptr


def parse_entry(data, ptr, metadata):
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
    print("fsize: %d" % get_integer(data, ptr, 4))
    ptr += 4
    # SHA-1
    ptr += 20
    # flags
    flags = get_integer(data, ptr, 2)
    ptr += 2
    if metadata["version"] == 2:
        assert (flags & 0x4000) == 0
    elif flags & 0x4000:
        ptr += 2
    name_length = flags & 0xFFF
    if name_length < 0xFFF:
        print("name: %s" % data[ptr:ptr+name_length])
        ptr += name_length
    else:
        name_end = data.find("\0", ptr)
        assert name_end != -1
        print("name: %s" % data[ptr:name_end])
        ptr = name_end

    if metadata["version"] != 4:
        # 1-8 nul bytes
        ptr += 8 - (ptr - entry_begin) % 8
    return ptr


# https://www.kernel.org/pub/software/scm/git/docs/technical/index-format.txt
def main(fname):
    try:
        f = open(fname)
    except Exception:
        print("open %s failed" % sys.argv[1])
        sys.exit(-1)

    data = f.read()

    metadata = {}
    ptr = 0

    ptr = parse_header(data, ptr, metadata)

    while ptr < metadata["endptr"]:
        ptr = parse_entry(data, ptr, metadata)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: %s index_file" % sys.argv[0])
        sys.exit(-1)
    main(sys.argv[1])
