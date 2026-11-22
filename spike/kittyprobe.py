#!/usr/bin/env python3
"""Enable the Kitty keyboard protocol (disambiguate), record raw input for a few
seconds, restore the mode and print what arrived. Used inside the spike's test
terminal only."""
import os, select, sys, termios, time, tty

seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 8
fd = sys.stdin.fileno()
old = termios.tcgetattr(fd)
tty.setraw(fd)
os.write(1, b"\x1b[>1u")  # push flags: disambiguate escape codes
os.write(1, b"KITTY-READY\r\n")
got = b""
end = time.monotonic() + seconds
try:
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            got += os.read(fd, 1024)
finally:
    os.write(1, b"\x1b[<u")  # pop flags
    termios.tcsetattr(fd, termios.TCSADRAIN, old)
print("KEYS " + repr(got))
