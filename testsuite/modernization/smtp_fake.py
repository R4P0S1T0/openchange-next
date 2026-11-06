#!/usr/bin/python3
"""A scripted SMTP server on stdio for the IMAP backend tests (mapistore:smtp_tunnel).

Usage: smtp_fake.py <command log> <DATA file> <mode>
mode: ok | rcpt553 (RCPT refused) | size100 (EHLO advertises SIZE 100)
Every command line goes to the log; AUTH PLAIN credentials as "AUTHDATA <base64>";
the received DATA, dot-unstuffed, to the DATA file.
"""
import sys

log_path, data_path, mode = sys.argv[1:4]
inp, out = sys.stdin.buffer, sys.stdout.buffer


def send(text):
    out.write(text.encode() + b"\r\n")
    out.flush()


with open(log_path, "a") as log:
    send("220 fake ESMTP")
    while True:
        raw = inp.readline()
        if not raw:
            break
        cmd = raw.decode(errors="replace").rstrip("\r\n")
        log.write(cmd + "\n")
        log.flush()
        verb = cmd.split(" ")[0].upper()
        if verb == "EHLO":
            for line in ("250-fake", "250-AUTH PLAIN", "250-PIPELINING"):
                send(line)
            send("250 SIZE 100" if mode == "size100" else "250 SIZE 10000000")
        elif verb == "AUTH":
            words = cmd.split()
            if len(words) < 3:
                send("334 ")
                words.append(inp.readline().decode().strip())
            log.write("AUTHDATA " + words[2] + "\n")
            send("235 ok")
        elif verb == "MAIL":
            send("250 ok")
        elif verb == "RCPT":
            send("553 refused" if mode == "rcpt553" else "250 ok")
        elif verb == "DATA":
            send("354 go")
            data = b""
            while True:
                line = inp.readline()
                if line in (b".\r\n", b".\n", b""):
                    break
                data += line[1:] if line.startswith(b"..") else line
            with open(data_path, "wb") as f:
                f.write(data)
            send("250 queued")
        elif verb in ("RSET", "NOOP"):
            send("250 ok")
        elif verb == "QUIT":
            send("221 bye")
            break
        else:
            send("502 unknown")
