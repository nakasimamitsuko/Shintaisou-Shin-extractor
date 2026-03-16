#!/usr/bin/env python3
"""
ScrPlayer 引擎工具集
- PAK 解包 (PACK/pack 格式)
- IMG 转 PNG (phim 格式, 支持 24bit/32bit)

用法:
  python scrplayer_tools.py unpack <data.pak> [output_dir]
  python scrplayer_tools.py img2png <input.img> <output.png> [scrplayer.exe]
  python scrplayer_tools.py img2png_batch <dir_with_imgs> [output_dir] [scrplayer.exe]

逆向自 ScrPlayer.exe
"""

import struct, sys, os
from pathlib import Path


class ExeTableLoader:
    """从 ScrPlayer.exe 提取 IMG 解码所需的全部静态 Huffman 表"""

    def __init__(self, exe_path):
        with open(exe_path, "rb") as f:
            self.data = f.read()
        self.image_base = 0x400000
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        ns = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        ohs = struct.unpack_from("<H", self.data, e_lfanew + 0x14)[0]
        so = e_lfanew + 0x18 + ohs
        self.sections = []
        for i in range(ns):
            o = so + i * 40
            va   = struct.unpack_from("<I", self.data, o + 12)[0]
            vs   = struct.unpack_from("<I", self.data, o + 8)[0]
            rp   = struct.unpack_from("<I", self.data, o + 20)[0]
            self.sections.append((va, vs, rp))

    def _r(self, va, sz):
        rva = va - self.image_base
        for sva, svs, srp in self.sections:
            if sva <= rva < sva + svs:
                off = srp + (rva - sva)
                return self.data[off:off + sz]
        raise ValueError(f"Cannot map VA 0x{va:08X}")

    def load_all(self):
        r = self._r
        return {
            'huf_main':           r(0x0044fd08, 0x4000),
            'huf_main_overflow':  r(0x00453d08, 0x4000),
            'huf_delta':          r(0x00458188, 0x800),
            'huf_delta_overflow': r(0x00458988, 0x800),
            'huf_pos_noalpha':    r(0x00457d08, 0x80),
            'huf_pos_alpha':      r(0x00457d88, 0x400),
            'alpha_pos_indirect': r(0x0044fc58, 22 * 8),
            'delta_b':            r(0x0044f7d0, 0xD8),
            'delta_g':            r(0x0044f8a8, 0xD8),
            'delta_r':            r(0x0044f980, 0xD8),
            'delta_ext':          r(0x0044fa58, 0x100),
            'alpha_ext':          r(0x0044fb58, 0x100),
            'predictor_init':     r(0x0044f6f8, 0x58),
        }


# ============================================================================
# PAK 解包
# ============================================================================

def unpack_pak(pak_path, output_dir):
    pak_path = Path(pak_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(pak_path, "rb") as f:
        pak = f.read()

    magic = pak[0:4]
    if magic not in (b'PACK', b'pack'):
        raise ValueError(f"非 PAK 文件, magic={magic}")

    idx_sz = struct.unpack_from("<I", pak, 4)[0]
    print(f"PAK: magic={magic} index_size=0x{idx_sz:X}")

    idx = pak[8:8 + idx_sz]
    entries = []
    pos = 0
    while pos + 9 <= len(idx):
        offset = struct.unpack_from("<I", idx, pos)[0]
        if offset == 0:
            break
        size = struct.unpack_from("<I", idx, pos + 4)[0]
        nlen = idx[pos + 8]
        name = idx[pos + 9:pos + 9 + nlen].split(b'\x00')[0].decode('ascii', errors='replace')
        entries.append((name, offset, size))
        pos += ((nlen + 9) & ~7) + 8

    print(f"文件数: {len(entries)}\n")
    for name, offset, size in entries:
        out_path = output_dir / name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(pak[offset:offset + size])
        print(f"  {name:40s} off=0x{offset:08X} sz=0x{size:X}")

    print(f"\n完成 → {output_dir}")
    return entries


# ============================================================================
# IMG (phim) 解码器
# ============================================================================

class BitReader:
    __slots__ = ('s', 'p', 'b', 'n')

    def __init__(self, data):
        self.s = data   # stream
        self.p = 0      # position
        self.b = 0      # bit buffer
        self.n = 0      # valid bits

    def _fill16(self, need):
        if self.n < need:
            if self.p + 1 < len(self.s):
                self.b |= (self.s[self.p] | (self.s[self.p+1] << 8)) << self.n
                self.p += 2
            elif self.p < len(self.s):
                self.b |= self.s[self.p] << self.n
                self.p += 1
            self.n += 16

    def _fill8(self, need):
        while self.n < need and self.p < len(self.s):
            self.b |= self.s[self.p] << self.n
            self.p += 1
            self.n += 8

    def huf16(self, tbl, bits, mask):
        self._fill16(bits)
        i = (self.b & mask) * 2
        nb = tbl[i]; sym = tbl[i+1]
        self.n -= nb; self.b >>= nb
        return sym

    def huf8(self, tbl, bits, mask):
        self._fill8(bits)
        i = (self.b & mask) * 2
        nb = tbl[i]; sym = tbl[i+1]
        self.n -= nb; self.b >>= nb
        return sym


class PhimDecoder:
    def __init__(self, tables):
        self.t = tables
        self.pred_init = []
        pi = tables['predictor_init']
        for i in range(11):
            self.pred_init.append([
                struct.unpack_from("<i", pi, i*8)[0],
                struct.unpack_from("<i", pi, i*8+4)[0]
            ])
        ai = tables['alpha_pos_indirect']
        self.alpha_ind = []
        for i in range(22):
            self.alpha_ind.append((
                struct.unpack_from("<i", ai, i*8)[0],
                struct.unpack_from("<i", ai, i*8+4)[0]
            ))

    def decode(self, data):
        if len(data) < 24 or data[0:4] != b'phim':
            raise ValueError(f"非 phim 格式: {data[0:4]}")

        _, _, x_off, y_off, w, h, bpp, _ = struct.unpack_from("<4sIHHHHHH", data)
        alpha = bpp == 0x20
        print(f"  {w}x{h} bpp={bpp} off=({x_off},{y_off}) alpha={alpha}")

        if w == 0 or h == 0:
            raise ValueError("尺寸为0")

        br = BitReader(data[24:])
        px = bytearray(w * h * 4)
        roff = [y * w * 4 for y in range(h)]

        zr = bytearray(w * 4)
        for i in range(0, w * 4, 4):
            zr[i+3] = 0xFF

        pred = [p[:] for p in self.pred_init]
        rows = [(zr, 0), (zr, 0), (zr, 0)]

        if alpha:
            self._dec32(br, w, h, px, roff, zr, pred, rows)
        else:
            self._dec24(br, w, h, px, roff, zr, pred, rows)

        return w, h, x_off, y_off, alpha, bytes(px)

    def _ext_delta(self, br):
        s = br.huf16(self.t['huf_delta'], 10, 0x3FF)
        if s == 0x41:
            s = br.huf16(self.t['huf_delta_overflow'], 10, 0x3FF) + 0x41
        return struct.unpack_from("b", self.t['delta_ext'], s)[0]

    def _alpha_delta(self, br):
        s = br.huf16(self.t['huf_delta'], 10, 0x3FF)
        if s == 0x41:
            s = br.huf16(self.t['huf_delta_overflow'], 10, 0x3FF) + 0x41
        return struct.unpack_from("b", self.t['alpha_ext'], s)[0]

    def _ref(self, rs, rx, rows, px):
        buf, base = rows[rs]
        off = base + rx * 4
        if 0 <= off <= len(buf) - 4:
            return buf[off], buf[off+1], buf[off+2], buf[off+3]
        return 0, 0, 0, 0xFF

    def _dec24(self, br, w, h, px, roff, zr, pred, rows):
        t = self.t
        for y in range(h):
            rows[2] = rows[1]; rows[1] = rows[0]; rows[0] = (px, roff[y])
            cb = roff[y]; x = 0
            while x < w:
                ms = br.huf16(t['huf_main'], 13, 0x1FFF)
                if ms == 0xB8:
                    ms = br.huf16(t['huf_main_overflow'], 13, 0x1FFF) + 0xB8

                ps = br.huf8(t['huf_pos_noalpha'], 6, 0x3F)
                dx = pred[ps][0]; rs = pred[ps][1]
                if ps:
                    pred[ps][0], pred[ps-1][0] = pred[ps-1][0], pred[ps][0]
                    pred[ps][1], pred[ps-1][1] = pred[ps-1][1], pred[ps][1]

                rx = dx + x

                if ms < 0xD8:
                    rb, rg, rr, ra = self._ref(rs, rx, rows, px)

                    db = struct.unpack_from("b", t['delta_b'], ms)[0]
                    if db == -3: db = self._ext_delta(br)
                    dg = struct.unpack_from("b", t['delta_g'], ms)[0]
                    if dg == -3: dg = self._ext_delta(br)
                    dr = struct.unpack_from("b", t['delta_r'], ms)[0]
                    if dr == -3: dr = self._ext_delta(br)

                    # 反编译: pixel[2] = ref_high16_byte - delta_b => R channel
                    # pixel[1] = ref_byte1 - delta_g => G channel
                    # pixel[0] = ref_byte0 - delta_r => B channel
                    # ref 作为 uint32 LE: byte0=B, byte1=G, byte2=R, byte3=A
                    o = cb + x * 4
                    px[o]   = (rb - dr) & 0xFF  # B = refB - delta_r
                    px[o+1] = (rg - dg) & 0xFF  # G = refG - delta_g
                    px[o+2] = (rr - db) & 0xFF  # R = refR - delta_b
                    px[o+3] = 0xFF
                    x += 1
                else:
                    cl = ms - 0xD6
                    buf, base = rows[rs]
                    brx = dx + x
                    for ci in range(cl):
                        so = base + (brx + ci) * 4
                        do = cb + (x + ci) * 4
                        if 0 <= so <= len(buf) - 4:
                            px[do:do+4] = buf[so:so+4]
                        else:
                            px[do:do+4] = b'\x00\x00\x00\xFF'
                    x += cl

    def _dec32(self, br, w, h, px, roff, zr, pred, rows):
        t = self.t
        for y in range(h):
            rows[2] = rows[1]; rows[1] = rows[0]; rows[0] = (px, roff[y])
            cb = roff[y]; x = 0
            while x < w:
                ms = br.huf16(t['huf_main'], 13, 0x1FFF)
                if ms == 0xB8:
                    ms = br.huf16(t['huf_main_overflow'], 13, 0x1FFF) + 0xB8

                pr = br.huf16(t['huf_pos_alpha'], 9, 0x1FF)
                pi, af = self.alpha_ind[pr]

                dx = pred[pi][0]; rs = pred[pi][1]
                if pi:
                    pred[pi][0], pred[pi-1][0] = pred[pi-1][0], pred[pi][0]
                    pred[pi][1], pred[pi-1][1] = pred[pi-1][1], pred[pi][1]

                rx = dx + x

                if ms < 0xD8:
                    rb, rg, rr, ra = self._ref(rs, rx, rows, px)

                    db = struct.unpack_from("b", t['delta_b'], ms)[0]
                    if db == -3: db = self._ext_delta(br)
                    dg = struct.unpack_from("b", t['delta_g'], ms)[0]
                    if dg == -3: dg = self._ext_delta(br)
                    dr = struct.unpack_from("b", t['delta_r'], ms)[0]
                    if dr == -3: dr = self._ext_delta(br)

                    o = cb + x * 4
                    px[o]   = (rb - dr) & 0xFF
                    px[o+1] = (rg - dg) & 0xFF
                    px[o+2] = (rr - db) & 0xFF

                    av = ra
                    if af:
                        av = (av - self._alpha_delta(br)) & 0xFF
                    px[o+3] = av
                    x += 1
                else:
                    cl = ms - 0xD6
                    buf, base = rows[rs]
                    brx = dx + x
                    for ci in range(cl):
                        so = base + (brx + ci) * 4
                        do = cb + (x + ci) * 4
                        if 0 <= so <= len(buf) - 4:
                            px[do:do+4] = buf[so:so+4]
                        else:
                            px[do:do+4] = b'\x00\x00\x00\xFF'
                    x += cl


def img_to_png(img_path, png_path, tables):
    from PIL import Image
    with open(img_path, "rb") as f:
        data = f.read()
    dec = PhimDecoder(tables)
    w, h, xo, yo, alpha, px = dec.decode(data)
    img = Image.frombytes("RGBA", (w, h), px)
    r, g, b, a = img.split()
    img = Image.merge("RGBA", (b, g, r, a))
    img.save(png_path, "PNG")
    print(f"  → {png_path}")


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "unpack":
        if len(sys.argv) < 3:
            print("用法: scrplayer_tools.py unpack <data.pak> [output_dir]"); sys.exit(1)
        pak = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(pak)[0] + "_unpacked"
        unpack_pak(pak, out)

    elif cmd == "img2png":
        if len(sys.argv) < 4:
            print("用法: scrplayer_tools.py img2png <in.img> <out.png> [exe]"); sys.exit(1)
        exe = sys.argv[4] if len(sys.argv) > 4 else "ScrPlayer.exe"
        img_to_png(sys.argv[2], sys.argv[3], ExeTableLoader(exe).load_all())

    elif cmd == "img2png_batch":
        if len(sys.argv) < 3:
            print("用法: scrplayer_tools.py img2png_batch <img_dir> [png_dir] [exe]"); sys.exit(1)
        ind = Path(sys.argv[2])
        outd = Path(sys.argv[3]) if len(sys.argv) > 3 else ind.parent / (ind.name + "_png")
        exe = sys.argv[4] if len(sys.argv) > 4 else "ScrPlayer.exe"
        outd.mkdir(parents=True, exist_ok=True)
        tables = ExeTableLoader(exe).load_all()
        ok = err = 0
        for f in sorted(ind.glob("*.img")):
            try:
                print(f"转换: {f.name}")
                img_to_png(str(f), str(outd / (f.stem + ".png")), tables)
                ok += 1
            except Exception as e:
                print(f"  ✗ {e}"); err += 1
        print(f"\n完成: {ok} 成功, {err} 失败")
    else:
        print(f"未知命令: {cmd}"); print(__doc__); sys.exit(1)


if __name__ == "__main__":
    main()
