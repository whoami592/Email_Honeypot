#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Email Honeypot - fake SMTP server that traps and logs spammers/attackers.

Coded by : Mr. Sabaz Ali Khan (Cyber Security Engineer)

It NEVER relays or delivers mail. Every message is accepted, saved to disk
for analysis, and logged as JSON lines. Uses only the Python standard library.

Usage:
    python3 email_honeypot.py                      # listens on 0.0.0.0:2525
    python3 email_honeypot.py --port 25            # needs root for port 25
    python3 email_honeypot.py --host 127.0.0.1 --port 2525 --hostname mail.example.com

Test it:
    python3 -c "import smtplib; s=smtplib.SMTP('127.0.0.1',2525); \
s.sendmail('a@evil.com',['b@victim.com'],'Subject: hi\\n\\nbuy now'); s.quit()"

Only deploy on systems/networks you own or are authorised to monitor.
"""

import argparse
import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import re
import signal
import sys
from email import message_from_bytes
from email.header import decode_header, make_header

BANNER = r"""
 ____    _    ____    _     _____     _    _     ___   _  ___   _    _    _   _
/ ___|  / \  | __ )  / \   |__  /    / \  | |   |_ _| | |/ / | | |  / \  | \ | |
\___ \ / _ \ |  _ \ / _ \    / /    / _ \ | |    | |  | ' /  | |_| | / _ \ |  \| |
 ___) / ___ \| |_) / ___ \  / /_   / ___ \| |___ | |  | . \  |  _  |/ ___ \| |\  |
|____/_/   \_\____/_/   \_\/____| /_/   \_\_____|___| |_|\_\ |_| |_/_/   \_\_| \_|

  ============================================================================
   [ EMAIL HONEYPOT ]   Fake SMTP Trap for Spammers & Attackers
   Coded by : Mr. Sabaz Ali Khan  |  Cyber Security Engineer
  ============================================================================
"""

MAX_LINE = 4096
MAX_MESSAGE = 5 * 1024 * 1024      # 5 MB per message
MAX_COMMANDS = 200                 # per connection
IDLE_TIMEOUT = 60                  # seconds


class Honeypot:
    def __init__(self, hostname, log_dir, auth_fail=True):
        self.hostname = hostname
        self.log_dir = log_dir
        self.mail_dir = os.path.join(log_dir, "captured_mail")
        self.log_file = os.path.join(log_dir, "honeypot_events.jsonl")
        self.auth_fail = auth_fail
        os.makedirs(self.mail_dir, exist_ok=True)
        self.stats = {"connections": 0, "messages": 0, "auth_attempts": 0}

    # ---------- logging ----------
    def log(self, event, ip, **data):
        rec = {
            "time": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "ip": ip,
            **data,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        extra = " ".join(f"{k}={v!r}" for k, v in data.items())
        print(f"[{rec['time']}] {event:<12} {ip:<15} {extra}", flush=True)

    # ---------- helpers ----------
    @staticmethod
    def _decode(value):
        try:
            return str(make_header(decode_header(value or "")))
        except Exception:
            return value or ""

    def save_message(self, ip, mail_from, rcpts, raw):
        sha = hashlib.sha256(raw).hexdigest()
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.mail_dir, f"{stamp}_{ip.replace(':', '-')}_{sha[:10]}.eml")
        with open(path, "wb") as f:
            f.write(raw)
        info = {"from": mail_from, "to": rcpts, "bytes": len(raw), "sha256": sha, "file": path}
        try:
            msg = message_from_bytes(raw)
            info["subject"] = self._decode(msg.get("Subject"))
            body = raw.decode("utf-8", "ignore")
            info["urls"] = sorted(set(re.findall(r"https?://[^\s\"'<>]+", body)))[:20]
            info["attachments"] = [
                p.get_filename() for p in msg.walk() if p.get_filename()
            ]
        except Exception:
            pass
        return info

    # ---------- connection handler ----------
    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ip = peer[0]
        self.stats["connections"] += 1
        self.log("CONNECT", ip, port=peer[1])

        async def send(line):
            writer.write((line + "\r\n").encode())
            await writer.drain()

        async def readline():
            data = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
            if len(data) > MAX_LINE:
                raise ValueError("line too long")
            return data

        mail_from, rcpts, helo = None, [], None
        try:
            await send(f"220 {self.hostname} ESMTP Postfix")
            for _ in range(MAX_COMMANDS):
                raw = await readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "ignore").strip()
                if not line:
                    continue
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()

                if cmd in ("EHLO", "HELO"):
                    helo = arg
                    self.log("HELO", ip, helo=arg)
                    if cmd == "EHLO":
                        writer.write(
                            (f"250-{self.hostname}\r\n250-SIZE {MAX_MESSAGE}\r\n"
                             "250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n").encode())
                        await writer.drain()
                    else:
                        await send(f"250 {self.hostname}")

                elif cmd == "AUTH":
                    await self.handle_auth(arg, ip, send, readline)

                elif cmd == "MAIL":
                    m = re.search(r"<(.*?)>", arg)
                    mail_from = m.group(1) if m else arg
                    rcpts = []
                    self.log("MAIL_FROM", ip, mail_from=mail_from)
                    await send("250 2.1.0 Ok")

                elif cmd == "RCPT":
                    m = re.search(r"<(.*?)>", arg)
                    rcpt = m.group(1) if m else arg
                    rcpts.append(rcpt)
                    self.log("RCPT_TO", ip, rcpt=rcpt)
                    await send("250 2.1.5 Ok")

                elif cmd == "DATA":
                    if not mail_from or not rcpts:
                        await send("503 5.5.1 Error: need MAIL and RCPT first")
                        continue
                    await send("354 End data with <CR><LF>.<CR><LF>")
                    chunks, size, too_big = [], 0, False
                    while True:
                        l = await readline()
                        if not l or l in (b".\r\n", b".\n"):
                            break
                        size += len(l)
                        if size > MAX_MESSAGE:
                            too_big = True
                            continue
                        chunks.append(l[1:] if l.startswith(b"..") else l)
                    if too_big:
                        await send("552 5.3.4 Message too big")
                    else:
                        info = self.save_message(ip, mail_from, rcpts, b"".join(chunks))
                        self.stats["messages"] += 1
                        self.log("MESSAGE", ip, helo=helo, **info)
                        await send("250 2.0.0 Ok: queued as " + info["sha256"][:10].upper())
                    mail_from, rcpts = None, []

                elif cmd == "RSET":
                    mail_from, rcpts = None, []
                    await send("250 2.0.0 Ok")
                elif cmd == "NOOP":
                    await send("250 2.0.0 Ok")
                elif cmd in ("VRFY", "EXPN"):
                    self.log(cmd, ip, arg=arg)
                    await send("252 2.0.0 Cannot VRFY user")
                elif cmd == "QUIT":
                    await send("221 2.0.0 Bye")
                    break
                else:
                    self.log("UNKNOWN_CMD", ip, line=line[:200])
                    await send("502 5.5.2 Error: command not recognized")
        except asyncio.TimeoutError:
            self.log("TIMEOUT", ip)
        except (ConnectionError, ValueError) as e:
            self.log("ERROR", ip, error=str(e))
        except Exception as e:  # never crash the trap
            self.log("ERROR", ip, error=repr(e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            self.log("DISCONNECT", ip)

    async def handle_auth(self, arg, ip, send, readline):
        """Capture credentials attackers try (PLAIN / LOGIN), then reject."""
        self.stats["auth_attempts"] += 1
        parts = arg.split()
        mech = parts[0].upper() if parts else ""
        user = pwd = None

        def b64(s):
            try:
                return base64.b64decode(s.encode()).decode("utf-8", "ignore")
            except Exception:
                return ""

        if mech == "PLAIN":
            if len(parts) > 1:
                blob = parts[1]
            else:
                await send("334 ")
                blob = (await readline()).decode().strip()
            fields = b64(blob).split("\x00")
            if len(fields) >= 3:
                user, pwd = fields[1], fields[2]
        elif mech == "LOGIN":
            if len(parts) > 1:
                user = b64(parts[1])
            else:
                await send("334 VXNlcm5hbWU6")
                user = b64((await readline()).decode().strip())
            await send("334 UGFzc3dvcmQ6")
            pwd = b64((await readline()).decode().strip())
        else:
            await send("504 5.5.4 Unrecognized authentication type")
            return

        self.log("AUTH", ip, mechanism=mech, username=user, password=pwd)
        if self.auth_fail:
            await send("535 5.7.8 Error: authentication failed")
        else:
            await send("235 2.7.0 Authentication successful")


async def main():
    ap = argparse.ArgumentParser(description="Email Honeypot by Mr. Sabaz Ali Khan")
    ap.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=2525, help="port (default 2525; 25 needs root)")
    ap.add_argument("--hostname", default="mail.example.com", help="fake server hostname")
    ap.add_argument("--log-dir", default="honeypot_data", help="where logs/mail are stored")
    ap.add_argument("--accept-auth", action="store_true",
                    help="pretend logins succeed (lures attackers into sending mail)")
    args = ap.parse_args()

    print(BANNER)
    hp = Honeypot(args.hostname, args.log_dir, auth_fail=not args.accept_auth)
    server = await asyncio.start_server(hp.handle, args.host, args.port)
    print(f"[*] Honeypot listening on {args.host}:{args.port}  (Ctrl+C to stop)")
    print(f"[*] Logs     : {hp.log_file}")
    print(f"[*] Mail dir : {hp.mail_dir}\n", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            pass
    try:
        async with server:
            await stop.wait()
    except asyncio.CancelledError:
        pass
    print(f"\n[*] Stopped. Stats: {hp.stats}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)
