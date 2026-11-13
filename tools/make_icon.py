"""Generate the app icon without external design tools."""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")
os.makedirs(ASSETS, exist_ok=True)

SIZE = 256
image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((8, 8, SIZE - 8, SIZE - 8), radius=54, fill=(15, 157, 138, 255))
# subtle highlight
draw.rounded_rectangle((8, 8, SIZE - 8, 120), radius=54, fill=(22, 178, 158, 255))
draw.rectangle((8, 80, SIZE - 8, 122), fill=(15, 157, 138, 255))

font_path = r"C:\Windows\Fonts\segoeuib.ttf"
try:
    font = ImageFont.truetype(font_path, 142)
except OSError:
    font = ImageFont.load_default()

text = "T"
box = draw.textbbox((0, 0), text, font=font)
tw, th = box[2] - box[0], box[3] - box[1]
draw.text(((SIZE - tw) / 2, (SIZE - th) / 2 - 10), text, font=font, fill=(255, 255, 255, 255))

# signal arcs
for radius, width in ((88, 10), (116, 9), (144, 8)):
    draw.arc(
        (SIZE // 2 - radius, SIZE // 2 - radius + 20, SIZE // 2 + radius, SIZE // 2 + radius + 20),
        start=200,
        end=340,
        fill=(255, 255, 255, 190),
        width=width,
    )

image.save(os.path.join(ASSETS, "icon.png"))
image.save(
    os.path.join(ASSETS, "icon.ico"),
    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
)
print("written", os.path.join(ASSETS, "icon.ico"))
