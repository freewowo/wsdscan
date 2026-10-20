#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 WSD Scan 的应用图标。

    python tools/make_icon.py

产物（写到仓库根目录，构建脚本直接引用）：
    wsdscan.ico   —— 多尺寸 ICO，16/20/24/32/40/48/64/128/256
    wsdscan.png   —— 256×256 PNG，PyInstaller 里做任务栏图标用

设计是扁平风格：蓝色圆角方底 + 白色文稿 + 深色扫描器机身，
机身中间一道青色扫描光束。画布 4 倍超采样（1024px）再 LANCZOS 缩到 256，
避免小尺寸边缘出现锯齿。
"""

import os
import sys

from PIL import Image, ImageDraw, ImageFilter

# 允许从仓库任意位置运行
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(OUT)

S = 4
BASE = 256
N = BASE * S

img = Image.new("RGBA", (N, N), (0, 0, 0, 0))

# ---------- 背景：圆角方 + 纵向渐变 ----------
grad = Image.new("RGBA", (N, N))
gd = ImageDraw.Draw(grad)
for y in range(N):
    t = y / N
    gd.line([(0, y), (N, y)],
            fill=(int(30 + 7 * t), int(58 + 41 * t), int(138 + 97 * t), 255))
mask = Image.new("L", (N, N), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, N - 1, N - 1], radius=N * 0.22, fill=255)
img.paste(grad, (0, 0), mask)
d = ImageDraw.Draw(img)

# ---------- 文稿 ----------
pw, ph = N * 0.38, N * 0.42
px, py = (N - pw) / 2, N * 0.125
d.rounded_rectangle([px, py, px + pw, py + ph], radius=N * 0.032,
                    fill=(255, 255, 255, 255))
for i, wf in enumerate((0.54, 0.70, 0.62, 0.42)):
    ly = py + ph * (0.17 + i * 0.16)
    d.rounded_rectangle([px + pw * 0.15, ly, px + pw * 0.15 + pw * wf,
                         ly + N * 0.021], radius=N * 0.0105,
                        fill=(203, 213, 225, 255))

# ---------- 扫描器机身 ----------
bx0, bx1 = N * 0.095, N * 0.905
sy, bh = N * 0.575, N * 0.315
# 机身投影
sh = Image.new("RGBA", (N, N), (0, 0, 0, 0))
ImageDraw.Draw(sh).rounded_rectangle(
    [bx0, sy + N * 0.012, bx1, sy + bh + N * 0.012],
    radius=N * 0.072, fill=(2, 6, 23, 110))
img.alpha_composite(sh.filter(ImageFilter.GaussianBlur(N * 0.012)))
d = ImageDraw.Draw(img)

d.rounded_rectangle([bx0, sy, bx1, sy + bh], radius=N * 0.072,
                    fill=(15, 23, 42, 255))
# 顶面高光条
d.rounded_rectangle([bx0, sy, bx1, sy + N * 0.030], radius=N * 0.048,
                    fill=(51, 65, 85, 255))

# ---------- 进稿口（内嵌细缝，不再外扩） ----------
slot_x0, slot_x1 = bx0 + N * 0.055, bx1 - N * 0.055
slot_y0 = sy + N * 0.012
slot_y1 = slot_y0 + N * 0.038
d.rounded_rectangle([slot_x0, slot_y0, slot_x1, slot_y1], radius=N * 0.019,
                    fill=(2, 6, 23, 255))

# ---------- 扫描光束 ----------
beam_top = sy + N * 0.088
beam_h = N * 0.024
glow = Image.new("RGBA", (N, N), (0, 0, 0, 0))
gg = ImageDraw.Draw(glow)
gg.rounded_rectangle([bx0 + N * 0.105, beam_top - N * 0.022,
                      bx1 - N * 0.105, beam_top + beam_h + N * 0.022],
                     radius=N * 0.02, fill=(56, 189, 248, 80))
img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(N * 0.010)))
d = ImageDraw.Draw(img)
d.rounded_rectangle([bx0 + N * 0.125, beam_top, bx1 - N * 0.125, beam_top + beam_h],
                    radius=N * 0.012, fill=(125, 211, 252, 255))
d.rounded_rectangle([bx0 + N * 0.175, beam_top + N * 0.007,
                     bx1 - N * 0.175, beam_top + beam_h - N * 0.007],
                    radius=N * 0.005, fill=(240, 249, 255, 255))

# ---------- 正面细节 ----------
fy = sy + bh * 0.62
d.rounded_rectangle([bx0 + N * 0.10, fy - N * 0.019, bx0 + N * 0.10 + N * 0.042,
                     fy + N * 0.019], radius=N * 0.021, fill=(71, 85, 105, 255))
d.ellipse([bx1 - N * 0.145, fy - N * 0.019, bx1 - N * 0.145 + N * 0.038,
           fy + N * 0.019], fill=(74, 222, 128, 255))

img = img.resize((BASE, BASE), Image.LANCZOS)
sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
img.save("wsdscan.ico", sizes=[(s, s) for s in sizes], format="ICO")
img.save("wsdscan.png", "PNG")

# 小尺寸预览条：把 16/32/48/64 并排放大 3 倍，用来看小尺寸下还认不认得出
if "--preview" in sys.argv:
    strip = Image.new("RGBA", (16 + 32 + 48 + 64 + 40, 64), (255, 255, 255, 255))
    x = 4
    for s in (16, 32, 48, 64):
        ic = img.resize((s, s), Image.LANCZOS)
        strip.paste(ic, (x, (64 - s) // 2), ic)
        x += s + 4
    strip.resize((strip.width * 3, strip.height * 3), Image.NEAREST).save(
        "_preview.png", "PNG")
    print("预览条已存到 _preview.png")
print("已生成 wsdscan.ico 与 wsdscan.png")
