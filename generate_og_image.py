#!/usr/bin/env python3
"""Generate OG image for social sharing. Run inside Docker container or with Pillow installed."""
import os
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Pillow not installed. Run: pip install Pillow")
    sys.exit(1)


def generate_og_image(title, subtitle, features=None, output_path="static/img/og-image.png"):
    """Generate a 1200x630 OG image with green gradient background."""
    width, height = 1200, 630
    img = Image.new("RGB", (width, height))
    draw = ImageDraw.Draw(img)

    # Green gradient background
    for y in range(height):
        r = int(5 + (y / height) * 20)
        g = int(150 - (y / height) * 50)
        b = int(105 - (y / height) * 40)
        draw.line([(0, y), (width, y)], fill=(r, g, b))

    # Use default font (works everywhere)
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
        subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
        small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
    except (OSError, IOError):
        title_font = ImageFont.load_default()
        subtitle_font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    # Title
    draw.text((60, 80), title, fill="white", font=title_font)

    # Subtitle
    draw.text((60, 160), subtitle, fill=(200, 255, 220), font=subtitle_font)

    # Features
    if features:
        y_pos = 260
        for feat in features[:4]:
            draw.text((80, y_pos), f"✓  {feat}", fill="white", font=small_font)
            y_pos += 45

    # Branding
    draw.text((60, height - 70), "tinyship.ai", fill=(200, 255, 220), font=subtitle_font)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path)
    print(f"✅ OG image saved to {output_path}")


if __name__ == "__main__":
    generate_og_image(
        title="DepScan",
        subtitle="Dependency Vulnerability Scanner",
        features=[
            "Scan package.json, requirements.txt, go.mod and more",
            "Live CVE results from OSV",
            "AI migration suggestions in full report",
        ],
    )
