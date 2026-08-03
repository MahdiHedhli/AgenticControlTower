#!/usr/bin/env python3
"""Render ACT app icon PNGs from the beacon-mark geometry in act-app-icon.svg.

Draws the exact same three primitives as the SVG (full-bleed #0A0E14 square,
#F5A623 triangle outline stroke-width 56, #F5A623 apex dot r 72 on a 1024 grid)
with Pillow at 4x supersample, then downsamples per target size. The stroked
triangle is rendered as outer-minus-inner similar triangles scaled about the
incenter, which is mathematically identical to an SVG miter-joined stroke here
(both miter ratios are under the default miter limit of 4).

Output PNGs are RGB (no alpha channel) as required for iOS marketing icons.

Usage: python3 render_app_icons.py <mobile-dir>
"""
import sys
from pathlib import Path

from PIL import Image, ImageDraw

BG = (10, 14, 20)        # #0A0E14
AMBER = (245, 166, 35)   # #F5A623

# Geometry on the 1024 master grid (favicon.svg geometry x8)
APEX = (512.0, 352.0)
BASE_R = (704.0, 800.0)
BASE_L = (320.0, 800.0)
STROKE = 56.0
DOT_C = (512.0, 224.0)
DOT_R = 72.0

SS = 4  # supersample factor -> 4096px master canvas

IOS_ICONS = {
    "Icon-App-20x20@1x.png": 20,
    "Icon-App-20x20@2x.png": 40,
    "Icon-App-20x20@3x.png": 60,
    "Icon-App-29x29@1x.png": 29,
    "Icon-App-29x29@2x.png": 58,
    "Icon-App-29x29@3x.png": 87,
    "Icon-App-40x40@1x.png": 40,
    "Icon-App-40x40@2x.png": 80,
    "Icon-App-40x40@3x.png": 120,
    "Icon-App-60x60@2x.png": 120,
    "Icon-App-60x60@3x.png": 180,
    "Icon-App-76x76@1x.png": 76,
    "Icon-App-76x76@2x.png": 152,
    "Icon-App-83.5x83.5@2x.png": 167,
    "Icon-App-1024x1024@1x.png": 1024,
}

ANDROID_ICONS = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}


def _dist(p, q):
    return ((p[0] - q[0]) ** 2 + (p[1] - q[1]) ** 2) ** 0.5


def _offset_triangle(a, b, c, delta):
    """Triangle offset by `delta` (outward if positive): similar triangle
    scaled about the incenter by (r + delta) / r, r = inradius."""
    la, lb, lc = _dist(b, c), _dist(c, a), _dist(a, b)  # opposite side lengths
    peri = la + lb + lc
    ix = (la * a[0] + lb * b[0] + lc * c[0]) / peri
    iy = (la * a[1] + lb * b[1] + lc * c[1]) / peri
    s = peri / 2.0
    area = abs(
        (b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1])
    ) / 2.0
    r = area / s
    k = (r + delta) / r
    return [
        ((p[0] - ix) * k + ix, (p[1] - iy) * k + iy) for p in (a, b, c)
    ]


def render_master():
    f = SS
    img = Image.new("RGB", (1024 * f, 1024 * f), BG)
    draw = ImageDraw.Draw(img)
    a = (APEX[0] * f, APEX[1] * f)
    b = (BASE_R[0] * f, BASE_R[1] * f)
    c = (BASE_L[0] * f, BASE_L[1] * f)
    half = STROKE * f / 2.0
    draw.polygon(_offset_triangle(a, b, c, +half), fill=AMBER)
    draw.polygon(_offset_triangle(a, b, c, -half), fill=BG)
    cx, cy, r = DOT_C[0] * f, DOT_C[1] * f, DOT_R * f
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=AMBER)
    return img


def main():
    mobile = Path(sys.argv[1]).resolve()
    master = render_master()

    ios_dir = mobile / "ios/Runner/Assets.xcassets/AppIcon.appiconset"
    for name, px in IOS_ICONS.items():
        master.resize((px, px), Image.LANCZOS).save(ios_dir / name)
        print(f"ios     {px:>4}px  {name}")

    res = mobile / "android/app/src/main/res"
    for density, px in ANDROID_ICONS.items():
        out = res / density / "ic_launcher.png"
        master.resize((px, px), Image.LANCZOS).save(out)
        print(f"android {px:>4}px  {density}/ic_launcher.png")


if __name__ == "__main__":
    main()
