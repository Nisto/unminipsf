import os
import sys
import struct
import zlib

EXE_HEADER_SIZE = 0x800

def get_u32_le(buf, off=0):
    return struct.unpack("<I", buf[off:off+4])[0]

def put_u32_le(buf, off, val):
    buf[off:off+4] = struct.pack("<I", val)

def parsepsf(path, get_tags=False):
    with open(path, "rb") as psf:
        psfbuf = psf.read()

    if psfbuf[:0x04] != b"PSF\x01":
        sys.exit("Invalid PSF file:\n%s" % path)

    size = get_u32_le(psfbuf[0x08:0x0C])
    crc = get_u32_le(psfbuf[0x0C:0x10])
    exebuf = zlib.decompress(psfbuf[0x10:0x10+size])

    if crc != zlib.crc32(psfbuf[0x10:0x10+size]):
        sys.exit("PSF file is corrupt:\n%s" % path)

    if get_tags:

        tags = { }

        if os.path.getsize(path) > 0x10+size:
            if psfbuf[0x10+size:0x10+size+5] == b"[TAG]":
                taglist = psfbuf[0x10+size+5:].decode("UTF-8").rstrip("\n").split("\n")
                for tag in taglist:
                    tagname, tagval = tag.split('=', 1)
                    tags[tagname] = tagval

        return (exebuf, tags)

    return exebuf

def loadexe(ram, exebuf):
    t_addr = get_u32_le(exebuf, 0x18)
    t_size = get_u32_le(exebuf, 0x1C)
    t_off = t_addr & 0x1FFFFF
    ram[t_off:t_off+t_size] = exebuf[EXE_HEADER_SIZE:EXE_HEADER_SIZE+t_size]
    return (t_addr, t_size)

psf_header_t = struct.Struct("<4sIII")

def exe2psf(exebuf):

    zbuf = zlib.compress(exebuf, 9)

    header = psf_header_t.pack(
        b"PSF\x01", 0, len(zbuf), zlib.crc32(zbuf)
    )

    return header + zbuf

def main(argc=len(sys.argv), argv=sys.argv):
    if argc != 2:
        print("Usage: %s <minipsf>" % argv[0])
        return 1

    minipsf_path = os.path.realpath(argv[1])

    if not os.path.isfile(minipsf_path):
        print("Invalid file path!")
        return 1

    minipsf_stem = os.path.splitext(minipsf_path)[0]

    minipsf_dir = os.path.dirname(minipsf_path)

    miniexebuf, tags = parsepsf(minipsf_path, True)

    if "_lib" not in tags:
        print("File is not a miniPSF:\n%s" % minipsf_path)
        return 1

    text_start = text_end = 0x80010000

    ram = bytearray(2 * 1024 * 1024)

    # technically we should recurse, but I've never seen it (+ I'm lazy)

    # import the library first
    libpath = os.path.join(minipsf_dir, tags["_lib"])
    libexebuf = parsepsf(libpath)
    pc = get_u32_le(libexebuf, 0x10)
    sp = get_u32_le(libexebuf, 0x30)
    t_addr, t_size = loadexe(ram, libexebuf)
    text_start = min(text_start, t_addr)
    text_end = max(text_end, t_addr + t_size)

    # superimpose the minipsf
    t_addr, t_size = loadexe(ram, miniexebuf)
    text_start = min(text_start, t_addr)
    text_end = max(text_end, t_addr + t_size)

    # superimpose any other libs
    for libn in range(2, 10):
        libtag = "_lib%d" % libn
        if libtag in tags:
            libpath = os.path.join(minipsf_dir, tags[libtag])
            libexebuf = parsepsf(libpath)
            t_addr, t_size = loadexe(ram, libexebuf)
            text_start = min(text_start, t_addr)
            text_end = max(text_end, t_addr + t_size)

    # build final EXE
    text_size = text_end - text_start

    outexebuf = bytearray(EXE_HEADER_SIZE + text_size)
    outexebuf[:EXE_HEADER_SIZE] = miniexebuf[:EXE_HEADER_SIZE]

    put_u32_le(outexebuf, 0x10, pc)
    put_u32_le(outexebuf, 0x18, text_start)
    put_u32_le(outexebuf, 0x1C, text_size)
    put_u32_le(outexebuf, 0x30, sp)

    outexebuf[EXE_HEADER_SIZE:EXE_HEADER_SIZE+text_size] = \
        ram[text_start & 0x1FFFFF : text_end & 0x3FFFFF]

    # write a standard PSF
    with open("%s.psf" % minipsf_stem, "wb") as psf:
        psf.write( exe2psf(outexebuf) )

    return 0

if __name__=="__main__":
    main()