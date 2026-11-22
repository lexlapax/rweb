#!/usr/bin/env python3
"""Observe what a Rex client sees across a Rex server restart (owner-authorized).

Creates its own rweb-test- session, opens control and data connections, restarts
rex.service, records how both connections close, then checks what survives:
reconnect token, data resume, session and block IDs, scrollback, the shell
process, and a fresh data stream. Destroys its session at the end. Prints only
markers it typed itself, not other terminal content.
"""
import base64, json, os, re, socket, struct, subprocess, threading, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "rex/server.sock")
T0 = time.monotonic()


def ts():
    return f"{time.monotonic() - T0:7.3f}s"


def log(*a):
    print(ts(), *a, flush=True)


class WS:
    def __init__(self, path, proto):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("closed during upgrade")
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise RuntimeError(head.split(b"\r\n")[0].decode())
        self.buf = bytearray(rest)

    def send(self, op, data):
        mask = os.urandom(4)
        n = len(data)
        if n < 126:
            hdr = bytes([0x80 | op, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x80 | op, 0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr = bytes([0x80 | op, 0x80 | 127]) + struct.pack(">Q", n)
        self.s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self, timeout=None):
        self.s.settimeout(timeout)

        def need(k):
            while len(self.buf) < k:
                chunk = self.s.recv(1 << 20)
                if not chunk:
                    raise EOFError
                self.buf.extend(chunk)
        while True:
            need(2)
            op, ln = self.buf[0] & 0x0F, self.buf[1] & 0x7F
            off = 2
            if ln == 126:
                need(4); ln = struct.unpack(">H", self.buf[2:4])[0]; off = 4
            elif ln == 127:
                need(10); ln = struct.unpack(">Q", self.buf[2:10])[0]; off = 10
            need(off + ln)
            data = bytes(self.buf[off:off + ln])
            del self.buf[:off + ln]
            if op == 9:
                self.send(10, data)
                continue
            return op, data


def close_info(data):
    if len(data) >= 2:
        return struct.unpack(">H", data[:2])[0], data[2:].decode(errors="replace")
    return None, ""


class Ctl:
    def __init__(self, token=None):
        self.ws = WS("/api/control", "rex.control.v1")
        hello = {"type": "hello", "api_revision": 19, "api_min_revision": 18,
                 "client": {"kind": "other", "name": "rweb-restart-probe"}}
        if token:
            hello["reconnect_token"] = token
        self.ws.send(1, json.dumps(hello).encode())
        _, d = self.ws.recv(5)
        self.welcome = json.loads(d)
        self.n = 0

    def call(self, method, payload, ok=True):
        self.n += 1
        rid = str(self.n)
        self.ws.send(1, json.dumps({"type": "request", "id": rid, "method": method, "payload": payload}).encode())
        while True:
            op, d = self.ws.recv(10)
            if op == 8:
                raise EOFError(close_info(d))
            m = json.loads(d)
            if m.get("type") == "response" and m.get("id") == rid:
                if "error" in m and ok:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("payload", m)

    def close(self):
        try:
            self.ws.send(8, struct.pack(">H", 1000))
        except OSError:
            pass


def data_open(first):
    d = WS("/api/data", "rex.data.terminal.v1")
    d.send(2, first)
    op, w = d.recv(5)
    return d, op, w


def welcome_info(w):
    return {"token": w[1:17], "resume_ms": struct.unpack("<I", w[20:24])[0], "nonce": struct.unpack("<Q", w[24:32])[0]}


def drain(d, secs):
    got = bytearray()
    end = time.monotonic() + secs
    while time.monotonic() < end:
        try:
            op, data = d.recv(0.2)
        except socket.timeout:
            continue
        if op == 8:
            log("data closed while draining:", close_info(data))
            break
        got += data
    return bytes(got)


def screen(ctl, sid, bid):
    r = ctl.call("com.superlogical.terminal.format", {"session_id": sid, "block_id": bid})
    return r.get("content", "")


def wait_marker(ctl, sid, bid, tag):
    for _ in range(30):
        m = re.findall(rf"{tag}-(\d+)-MARK", screen(ctl, sid, bid))
        if m:
            return m[-1]
        time.sleep(0.2)
    return None


def block_ids(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            block_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            block_ids(v, out)
    elif isinstance(obj, str) and obj.startswith("block:"):
        out.add(obj)
    return out


def watch(name, ws, events):
    while True:
        try:
            op, data = ws.recv(60)
        except socket.timeout:
            events.append((ts(), name, "timeout"))
            return
        except (EOFError, OSError) as e:
            events.append((ts(), name, f"eof/{type(e).__name__}"))
            return
        if op == 8:
            events.append((ts(), name, "close", close_info(data)))
            return
        if op == 1:
            m = json.loads(data)
            events.append((ts(), name, "text", m.get("type"), m.get("event", {}).get("type") if isinstance(m.get("event"), dict) else m.get("event")))
        else:
            events.append((ts(), name, "binary", len(data)))


def main():
    label = "rweb-test-restart-" + os.urandom(3).hex()
    ctl = Ctl()
    log("client", ctl.welcome["client"]["id"], "resumed:", ctl.welcome["client"].get("resumed"))
    st = ctl.call("server.status", {})
    log("before: pid", st["pid"], "instance", st["instance_id"], "started", st["started_at"], "sessions", st["session_count"])
    cr = ctl.call("session.create", {"label": label, "initial_windows": [{"layout": {"block": {"flavor": "com.superlogical.terminal.shell"}}}]})
    sid, bid = cr["session_id"], cr["initial_windows"][0]["block_ids"][0]
    log("created", label, sid, bid)
    destroyed = False
    try:
        ctl.call("session.attach", {"session_id": sid})
        v = ctl.call("session.view", {"session_id": sid})
        rev_a, blocks_a = v.get("revision"), block_ids(v, set())
        log("view before: revision", rev_a, "blocks", sorted(blocks_a))
        t = ctl.call("data.connect", {"session_id": sid, "block_id": bid, "data_ref_id": "terminal", "subprotocol": "rex.data.terminal.v1"})["ticket"]
        d, op, w = data_open(b"\x01" + base64.urlsafe_b64decode(t + "=="))
        assert w[0] == 0x81, w
        wi = welcome_info(w)
        log("data welcome: resume_ms", wi["resume_ms"], "nonce", wi["nonce"])
        count = len(drain(d, 1.0))
        ctl.call("com.superlogical.terminal.write", {"session_id": sid, "block_id": bid, "args": {"data": "echo PRE-$$-MARK\n"}})
        pid_a = wait_marker(ctl, sid, bid, "PRE")
        count += len(drain(d, 0.5))
        log("shell pid before:", pid_a, "stream bytes so far:", count)

        # Control: drop the control connection without a close frame, no restart.
        old_id = ctl.welcome["client"]["id"]
        ctl.ws.s.shutdown(socket.SHUT_RDWR); ctl.ws.s.close()
        ctl = Ctl(token=ctl.welcome["client"]["reconnect_token"])
        log("control drop without restart: resumed", ctl.welcome["client"].get("resumed"), "same client", ctl.welcome["client"]["id"] == old_id)

        events = []
        th = [threading.Thread(target=watch, args=("control", ctl.ws, events)),
              threading.Thread(target=watch, args=("data", d, events))]
        for x in th:
            x.start()
        log("restarting rex.service")
        r = subprocess.run(["systemctl", "--user", "restart", "rex.service"], capture_output=True, text=True)
        log("systemctl returned", r.returncode, r.stderr.strip())
        for x in th:
            x.join(10)
        for e in events:
            print("   ", *e, flush=True)

        # Reconnect the control connection with the old token.
        for i in range(50):
            try:
                ctl2 = Ctl(token=ctl.welcome["client"]["reconnect_token"])
                break
            except Exception as e:
                if i == 0:
                    log("first reconnect attempt failed:", type(e).__name__, e)
                time.sleep(0.1)
        log("reconnected with token; resumed:", ctl2.welcome["client"].get("resumed"), "same client", ctl2.welcome["client"]["id"] == ctl.welcome["client"]["id"])
        ctl = ctl2
        st2 = ctl.call("server.status", {})
        log("after: pid", st2["pid"], "instance", st2["instance_id"], "started", st2["started_at"], "sessions", st2["session_count"])
        ls = ctl.call("session.list", {})
        sessions = ls.get("sessions", ls)
        labels = [(s.get("label"), s.get("session_id") or s.get("id")) for s in sessions]
        log("sessions after:", labels)

        # Try to resume the old data stream.
        try:
            d2, op, w2 = data_open(b"\x02" + wi["token"] + struct.pack("<Q", count))
            if op == 2 and w2[0] == 0x82:
                log("data RESUME rejected, reason", hex(w2[1]))
            else:
                log("data RESUME answered", w2[:1].hex(), len(w2))
                d2.send(8, struct.pack(">H", 1000))
        except Exception as e:
            log("data RESUME failed:", type(e).__name__, e)

        if not any(x[1] == sid for x in labels):
            log("test session NOT restored")
            destroyed = True
            return
        a = ctl.call("session.attach", {"session_id": sid})
        v = ctl.call("session.view", {"session_id": sid})
        rev_b, blocks_b = v.get("revision"), block_ids(v, set())
        log("view after: revision", rev_b, "(before", rev_a, ") blocks", sorted(blocks_b), "same:", blocks_a == blocks_b)
        scr = screen(ctl, sid, bid)
        log("PRE marker still on screen/scrollback:", bool(re.search(r"PRE-\d+-MARK", scr)))
        ctl.call("com.superlogical.terminal.write", {"session_id": sid, "block_id": bid, "args": {"data": "echo POST-$$-MARK\n"}})
        pid_b = wait_marker(ctl, sid, bid, "POST")
        log("shell pid after:", pid_b, "(before", pid_a, ")")
        t = ctl.call("data.connect", {"session_id": sid, "block_id": bid, "data_ref_id": "terminal", "subprotocol": "rex.data.terminal.v1"})["ticket"]
        d3, op, w3 = data_open(b"\x01" + base64.urlsafe_b64decode(t + "=="))
        if w3[0] == 0x81:
            wi3 = welcome_info(w3)
            got = drain(d3, 1.0)
            log("new data stream: nonce", wi3["nonce"], "(before", wi["nonce"], ") bytes", len(got), "snapshot magic", got[:8])
            d3.send(8, struct.pack(">H", 1000))
        else:
            log("new data stream rejected", w3.hex())
    finally:
        if not destroyed:
            try:
                ctl.call("session.destroy", {"session_id": sid})
                log("destroyed", sid)
            except Exception as e:
                try:
                    c3 = Ctl()
                    c3.call("session.destroy", {"session_id": sid})
                    log("destroyed", sid, "on a new connection")
                    c3.close()
                except Exception as e2:
                    log("DESTROY FAILED", e, e2)
        ctl.close()


if __name__ == "__main__":
    main()
