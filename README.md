# 📧 Email Honeypot

A lightweight **fake SMTP server** that traps and logs spammers and attackers.
It **never relays or delivers mail** — every message is accepted, saved to disk for analysis, and recorded as structured JSON logs.

> **Coded by:** Mr. Sabaz Ali Khan — Cyber Security Engineer

---

## ✨ Features

- Realistic SMTP dialogue (`220 ... ESMTP Postfix`, `EHLO/HELO`, `MAIL`, `RCPT`, `DATA`, `RSET`, `NOOP`, `VRFY/EXPN`, `QUIT`)
- **Credential capture** for `AUTH PLAIN` and `AUTH LOGIN` attempts (username + password logged)
- Optional **"accept auth" mode** that pretends logins succeed, luring attackers into sending mail
- Every captured message saved as a `.eml` file named with timestamp, source IP and SHA-256 prefix
- Automatic extraction of **subject, URLs (up to 20) and attachment names**
- **JSON Lines** event log, easy to feed into SIEM tools, `jq`, or scripts
- Built-in protections: max line length, max message size (5 MB), max commands per connection (200), idle timeout (60 s)
- Asynchronous (`asyncio`) — handles many connections at once
- **Zero dependencies** — Python standard library only

---

## 📋 Requirements

- Python **3.8+**
- Linux, macOS or Windows (signal handling falls back gracefully on Windows)
- Root/Administrator privileges only if binding to a port below 1024 (e.g. port 25)

---

## 🚀 Usage

```bash
# Default: listens on 0.0.0.0:2525
python3 email_honeypot.py

# Standard SMTP port (requires root)
sudo python3 email_honeypot.py --port 25

# Custom bind address, port and fake hostname
python3 email_honeypot.py --host 127.0.0.1 --port 2525 --hostname mail.example.com

# Pretend authentication succeeds
python3 email_honeypot.py --accept-auth
```

### Command-line options

| Option          | Default              | Description                                              |
|-----------------|----------------------|----------------------------------------------------------|
| `--host`        | `0.0.0.0`            | Address to bind to                                       |
| `--port`        | `2525`               | Port to listen on (port 25 needs root)                   |
| `--hostname`    | `mail.example.com`   | Hostname the fake server presents                        |
| `--log-dir`     | `honeypot_data`      | Directory where logs and captured mail are stored        |
| `--accept-auth` | off                  | Respond "authentication successful" to any login attempt |

---

## 🧪 Quick Test

With the honeypot running locally, send it a test message:

```bash
python3 -c "import smtplib; s=smtplib.SMTP('127.0.0.1',2525); \
s.sendmail('a@evil.com',['b@victim.com'],'Subject: hi\n\nbuy now'); s.quit()"
```

You should see the connection, `MAIL_FROM`, `RCPT_TO` and `MESSAGE` events printed in the console and saved to disk.

---

## 📂 Output Structure

```
honeypot_data/
├── honeypot_events.jsonl      # all events, one JSON object per line
└── captured_mail/
    └── 20261109_101500_203.0.113.7_a1b2c3d4e5.eml
```

### Logged events

| Event         | Meaning                                         |
|---------------|-------------------------------------------------|
| `CONNECT`     | New client connection (IP + source port)        |
| `HELO`        | Client greeting / claimed hostname              |
| `AUTH`        | Login attempt: mechanism, username, password    |
| `MAIL_FROM`   | Envelope sender                                 |
| `RCPT_TO`     | Envelope recipient                              |
| `MESSAGE`     | Saved mail: sender, recipients, subject, size, SHA-256, URLs, attachments, file path |
| `VRFY` / `EXPN` | Address-probing attempts                      |
| `UNKNOWN_CMD` | Unrecognised command (first 200 chars)          |
| `TIMEOUT` / `ERROR` | Idle timeout or connection error          |
| `DISCONNECT`  | Connection closed                               |

### Example log line

```json
{"time": "2026-11-09T10:15:00+00:00", "event": "AUTH", "ip": "203.0.113.7", "mechanism": "PLAIN", "username": "admin", "password": "123456"}
```

### Handy analysis commands

```bash
# Top attacking IPs
jq -r '.ip' honeypot_data/honeypot_events.jsonl | sort | uniq -c | sort -rn | head

# All captured credentials
jq -c 'select(.event=="AUTH") | {ip, username, password}' honeypot_data/honeypot_events.jsonl

# All URLs found in captured spam
jq -r 'select(.event=="MESSAGE") | .urls[]?' honeypot_data/honeypot_events.jsonl | sort -u
```

---

## 🛡️ Safety Notes

- The honeypot **does not forward or deliver** any email.
- Captured messages may contain **malware, phishing links or malicious attachments**. Never open `.eml` files in a normal mail client on a production machine — analyse them in an isolated environment.
- Run it as a **non-privileged user**. If you need port 25, prefer port redirection (e.g. `iptables`/`nftables` from 25 → 2525) instead of running as root.
- Monitor disk usage of `honeypot_data/`, since every message (up to 5 MB each) is stored.

---

## ⚖️ Legal Disclaimer

Deploy this tool **only on systems and networks you own or are explicitly authorised to monitor**. The author is not responsible for misuse. Check local laws and your organisation's policies regarding the collection of attacker data and credentials.

---

## 👤 Author

**Mr. Sabaz Ali Khan** — Cyber Security Engineer
