#!/usr/bin/env python3
"""Gera o ícone PGP Desk (assets/pgp-desk.png)."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "pgp-desk.png"
SIZE = 512


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    margin, radius = 28, 96
    bg = (18, 42, 74, 255)
    accent = (56, 189, 148, 255)
    gold = (245, 200, 66, 255)
    white = (240, 248, 255, 255)
    shield_fill = (28, 64, 110, 255)

    d.rounded_rectangle((margin, margin, SIZE - margin, SIZE - margin), radius=radius, fill=bg)

    cx, cy = SIZE // 2, SIZE // 2 + 8
    shield = [
        (cx, cy - 170),
        (cx + 140, cy - 130),
        (cx + 140, cy + 40),
        (cx, cy + 175),
        (cx - 140, cy + 40),
        (cx - 140, cy - 130),
    ]
    d.polygon(shield, fill=shield_fill, outline=accent)
    d.line(shield + [shield[0]], fill=accent, width=10, joint="curve")

    kx, ky = cx - 10, cy + 10
    d.ellipse((kx - 70, ky - 95, kx + 20, ky - 5), fill=gold, outline=(180, 140, 30, 255), width=3)
    d.ellipse((kx - 48, ky - 73, kx - 2, ky - 27), fill=shield_fill)
    d.rectangle((kx - 8, ky - 30, kx + 95, ky - 8), fill=gold)
    for tx in (kx + 45, kx + 70):
        d.rectangle((tx, ky - 8, tx + 16, ky + 18), fill=gold)

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
    except OSError:
        font = ImageFont.load_default()
    text = "PGP"
    bbox = d.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    d.text((cx - tw / 2, cy + 95 - th / 2), text, font=font, fill=white)

    img.save(OUT, "PNG")
    for s in (256, 128, 64, 48):
        img.resize((s, s), Image.Resampling.LANCZOS).save(OUT.with_name(f"pgp-desk-{s}.png"))
    print(f"Ícone salvo em {OUT}")


if __name__ == "__main__":
    main()
