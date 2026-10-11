"""Generate packaging/lunatic.ico (original artwork: crescent + scan lines on deep black)."""
from pathlib import Path

from PIL import Image, ImageDraw

S = 256
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((8, 8, S - 8, S - 8), radius=48, fill=(7, 9, 12, 255), outline=(47, 140, 255, 255), width=8)
d.ellipse((48, 40, 208, 200), fill=(47, 140, 255, 255))           # moon
d.ellipse((92, 28, 236, 172), fill=(7, 9, 12, 255))               # crescent cut
for i, y in enumerate(range(150, 220, 18)):                        # scan lines
    d.rounded_rectangle((60 + i * 6, y, 196 - i * 6, y + 7), radius=3, fill=(197, 204, 214, 255))
out = Path(__file__).with_name("lunatic.ico")
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.save(out.with_suffix(".png"))
print(out)
