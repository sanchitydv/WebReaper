"""Generate icon.png / icon.ico / icon.icns for WebReaper."""
import os, sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Install pillow: pip install pillow")
    sys.exit(1)

SIZE = 512
img  = Image.new("RGBA", (SIZE, SIZE), (10, 14, 26, 255))
draw = ImageDraw.Draw(img)

# Red skull-ish circle background
draw.ellipse([40, 40, SIZE-40, SIZE-40], fill=(26, 0, 0, 255), outline=(255, 51, 51, 255), width=8)

# Big W glyph in red
try:
    font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Courier New Bold.ttf", 300)
except Exception:
    font = ImageFont.load_default()

text = "W"
bbox = draw.textbbox((0, 0), text, font=font)
tw, th = bbox[2]-bbox[0], bbox[3]-bbox[1]
draw.text(((SIZE-tw)//2 - bbox[0], (SIZE-th)//2 - bbox[1] - 20), text, fill=(255, 51, 51, 255), font=font)

out_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# PNG
png_path = os.path.join(out_dir, "icon.png")
img.save(png_path)
print(f"Saved {png_path}")

# ICO (Windows)
ico_path = os.path.join(out_dir, "icon.ico")
img.save(ico_path, format="ICO", sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])
print(f"Saved {ico_path}")

# ICNS (macOS) — requires iconutil or just embed PNG
icns_path = os.path.join(out_dir, "icon.icns")
if sys.platform == "darwin":
    import subprocess, tempfile, shutil
    iconset = tempfile.mkdtemp(suffix=".iconset")
    for sz in [16, 32, 64, 128, 256, 512]:
        resized = img.resize((sz, sz), Image.LANCZOS)
        resized.save(os.path.join(iconset, f"icon_{sz}x{sz}.png"))
        resized2 = img.resize((sz*2, sz*2), Image.LANCZOS)
        resized2.save(os.path.join(iconset, f"icon_{sz}x{sz}@2x.png"))
    subprocess.run(["iconutil", "-c", "icns", iconset, "-o", icns_path], check=True)
    shutil.rmtree(iconset)
    print(f"Saved {icns_path}")
else:
    img.save(icns_path, format="PNG")   # fallback on non-Mac
    print(f"Saved {icns_path} (PNG fallback)")
