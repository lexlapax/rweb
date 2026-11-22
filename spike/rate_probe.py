#!/usr/bin/env python3
"""Measure how fast Rex delivers a test block's data stream to a bare client.

Usage: rate_probe.py SESSION BLOCK SECONDS
Attaches to the given rweb-test- session only, opens one data stream, counts
bytes per 100 ms and prints them. No output is stored.
"""
import base64, json, os, socket, struct, sys, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "rex/server.sock")


def ws_connect(path, proto):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    head, rest = buf.split(b"\r\n\r\n", 1)
    assert b" 101 " in head.split(b"\r\n")[0], head
    return s, bytearray(rest)


def send(s, op, data):
    mask = os.urandom(4)
    n = len(data)
    hdr = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def recv(s, buf):
    def need(k):
        while len(buf) < k:
            chunk = s.recv(1 << 20)
            if not chunk:
                raise EOFError
            buf.extend(chunk)
    need(2)
    op, ln = buf[0] & 0x0F, buf[1] & 0x7F
    off = 2
    if ln == 126:
        need(4); ln = struct.unpack(">H", buf[2:4])[0]; off = 4
    elif ln == 127:
        need(10); ln = struct.unpack(">Q", buf[2:10])[0]; off = 10
    need(off + ln)
    data = bytes(buf[off:off + ln])
    del buf[:off + ln]
    return op, data


def main():
    session, block, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    assert session.startswith("session:") and block.startswith("block:")
    c, cb = ws_connect("/api/control", "rex.control.v1")
    send(c, 1, json.dumps({"type": "hello", "api_revision": 19, "client": {"kind": "other", "name": "rweb-rate-probe"}}).encode())
    recv(c, cb)

    def call(i, method, payload):
        send(c, 1, json.dumps({"type": "request", "id": str(i), "method": method, "payload": payload}).encode())
        while True:
            _, d = recv(c, cb)
            m = json.loads(d)
            if m.get("type") == "response" and m.get("id") == str(i):
                assert "error" not in m, m
                return m["payload"]

    call(1, "session.attach", {"session_id": session})
    t = call(2, "data.connect", {"session_id": session, "block_id": block, "data_ref_id": "terminal",
                                 "subprotocol": "rex.data.terminal.v1"})["ticket"]
    d, db = ws_connect("/api/data", "rex.data.terminal.v1")
    send(d, 2, b"\x01" + base64.urlsafe_b64decode(t + "=="))
    _, welcome = recv(d, db)
    assert welcome[0] == 0x81, welcome
    print("ready", flush=True)
    d.settimeout(0.05)
    start = time.monotonic()
    bucket, total, sizes = [0] * int(seconds * 10 + 1), 0, []
    while time.monotonic() - start < seconds:
        try:
            op, data = recv(d, db)
        except socket.timeout:
            continue
        if op == 8:
            break
        i = int((time.monotonic() - start) * 10)
        if i < len(bucket):
            bucket[i] += len(data)
        total += len(data)
        sizes.append(len(data))
    active = [i for i, b in enumerate(bucket) if b > 1000]
    if active:
        span = (active[-1] - active[0] + 1) / 10
        print(f"bytes={total} messages={len(sizes)} max_msg={max(sizes)} span={span:.1f}s rate={total / span / 1024:.0f} KB/s")
    print("per-100ms:", " ".join(f"{i}:{b}" for i, b in enumerate(bucket) if b))
    send(d, 8, struct.pack(">H", 1000))
    send(c, 8, struct.pack(">H", 1000))


if __name__ == "__main__":
    main()
