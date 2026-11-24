#!/usr/bin/env python3
"""Render docs/dissertation/nimbus-dissertation.md to PDF with headless Chrome (G5).

    python3 scripts/build_pdf.py            # needs: python3 -m pip install markdown; Google Chrome or Chromium
Writes docs/dissertation/nimbus-dissertation.pdf. SVG figures are embedded from docs/img/.
"""
import os, shutil, subprocess, sys, tempfile

import markdown

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC = os.path.join(ROOT, "docs", "dissertation", "nimbus-dissertation.md")
OUT = os.path.join(ROOT, "docs", "dissertation", "nimbus-dissertation.pdf")

CSS = """
@page { size: A4; margin: 18mm 17mm 20mm; }
body { font: 10.5pt/1.5 Georgia, "Times New Roman", serif; color: #111; }
h1 { font: bold 22pt/1.2 Helvetica, Arial, sans-serif; margin: 0 0 6pt; }
h2 { font: bold 14pt/1.3 Helvetica, Arial, sans-serif; margin: 20pt 0 6pt; break-after: avoid; }
h2:not(:first-of-type) { break-before: page; }
p, li { text-align: justify; hyphens: auto; }
code { font: 9pt Menlo, Consolas, monospace; background: #f3f4f6; padding: 0 2px; }
table { border-collapse: collapse; width: 100%; font: 8.5pt/1.35 Helvetica, Arial, sans-serif; margin: 8pt 0; break-inside: avoid; }
th, td { border: 1px solid #cbd5e1; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #f1f5f9; }
img { width: 100%; break-inside: avoid; margin: 6pt 0 0; }
p > em:only-child { display: block; font-size: 9pt; color: #374151; text-align: center; }
hr { border: 0; border-top: 1px solid #cbd5e1; }
"""


def chrome():
    for c in [
        os.environ.get("CHROME"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ]:
        if c and os.path.exists(c):
            return c
    sys.exit("Chrome/Chromium not found (set CHROME=...)")


def main():
    with open(SRC, encoding="utf-8") as f:
        md = f.read()
    body = markdown.markdown(md, extensions=["tables", "sane_lists"])
    base = "file://" + os.path.dirname(SRC) + "/"
    html = (
        f'<!doctype html><html><head><meta charset="utf-8"><base href="{base}">'
        f"<title>Nimbus Chain dissertation</title><style>{CSS}</style></head><body>{body}</body></html>"
    )
    with tempfile.TemporaryDirectory() as d:
        page = os.path.join(d, "d.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(html)
        subprocess.run(
            [
                chrome(),
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                "--allow-file-access-from-files",
                f"--print-to-pdf={OUT}",
                "file://" + page,
            ],
            check=True,
            capture_output=True,
        )
    print(OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()
