"""Capture the demo window for the README screenshot."""

from __future__ import annotations

import ctypes
import os
import sys
import time
import tkinter as tk
from ctypes import wintypes

from PIL import ImageGrab

# Make Tk coordinates match physical pixels so the capture is not half a window
# on a HiDPI desktop.
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from tgct526g.app import App  # noqa: E402

root = tk.Tk()
app = App(root)
app.load_demo()
root.update()
root.lift()
root.attributes("-topmost", True)
root.update()
time.sleep(1.0)
root.update()

hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
rect = wintypes.RECT()
ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
image = ImageGrab.grab(
    bbox=(rect.left, rect.top, rect.right, rect.bottom),
    all_screens=True,
)
# Keep the README asset reasonable while preserving layout.
if image.width > 1400:
    image = image.resize((1400, round(image.height * 1400 / image.width)))
image.save(os.path.join(ROOT, "docs", "screenshot.png"))
root.destroy()
print("saved", os.path.join(ROOT, "docs", "screenshot.png"), image.size)
