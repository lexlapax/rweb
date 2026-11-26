#!/usr/bin/env python3
"""Write a Windows icon (.ico) whose entries are the given PNG files, stored as PNG.

Usage: ico.py OUT.ico IN.png [IN.png ...]

Each PNG must be square and at most 256 pixels wide. Standard library only.
"""
import struct
import sys

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_size(data, name):
    if data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        sys.exit("%s: not a PNG file" % name)
    width, height = struct.unpack(">II", data[16:24])
    if width != height or not 1 <= width <= 256:
        sys.exit("%s: %dx%d is not a square of at most 256 pixels" % (name, width, height))
    return width


def main(out, inputs):
    images = []
    for name in inputs:
        with open(name, "rb") as f:
            data = f.read()
        images.append((png_size(data, name), data))
    images.sort(key=lambda image: image[0])

    header = struct.pack("<HHH", 0, 1, len(images))  # reserved, type 1 = icon, count
    offset = len(header) + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in images:
        # width, height (0 means 256), colours, reserved, planes, bits per pixel, size, offset
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    with open(out, "wb") as f:
        f.write(header + entries + blobs)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__.strip())
    main(sys.argv[1], sys.argv[2:])
