# ScrPlayer Tools

ScrPlayer 引擎资源提取工具，支持 PAK 解包和 IMG (phim) 图像转 PNG。

通过逆向 ScrPlayer.exe 反编译代码还原出完整的文件格式和压缩算法。

## 功能

- **PAK 解包** — 支持 `PACK` / `pack` 两种 magic 格式
- **IMG → PNG** — 支持 24bit (BGR) 和 32bit (BGRA) 两种像素深度
- **批量转换** — 一键转换整个目录

## 依赖

- Python 3.6+
- Pillow (`pip install Pillow`)
- 游戏本体的 `ScrPlayer.exe`（运行时从中提取解码表）

## 用法

```bash
# 解包 PAK
python scrplayer_tools.py unpack data.pak [output_dir]

# 单文件转换
python scrplayer_tools.py img2png input.img output.png [ScrPlayer.exe]

# 批量转换
python scrplayer_tools.py img2png_batch img_dir/ [png_dir/] [ScrPlayer.exe]
```

`ScrPlayer.exe` 参数可选，默认在当前目录查找。

## 格式说明

### PAK

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| +0x00 | 4 | magic | `PACK` (排序) 或 `pack` (无排序) |
| +0x04 | 4 | index_size | 索引区字节数 |

索引条目为变长结构：`offset(4) + size(4) + name_len(1) + name(N)`，步进 `((name_len + 9) & ~7) + 8`。

### IMG (phim)

24 字节头部：

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| +0x00 | 4 | magic | `phim` |
| +0x04 | 4 | — | 保留 |
| +0x08 | 2 | x_offset | 显示偏移 X |
| +0x0A | 2 | y_offset | 显示偏移 Y |
| +0x0C | 2 | width | 宽度 |
| +0x0E | 2 | height | 高度 |
| +0x10 | 2 | bpp | `0x18`=24bit, `0x20`=32bit |

压缩算法：静态 Huffman + 行间差分预测 + MRU 环形缓冲。解码表硬编码在 ScrPlayer.exe 的 `.rdata` 段中，工具运行时自动提取。

## License

MIT
