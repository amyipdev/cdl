import socket 
from base64 import b64encode
import sys
import os
from pathlib import Path
import json
import shlex
import subprocess

from aes import AESHandler

SEARCH_DIRECTORIES = (
    os.getcwd(),
    str(Path.home()),
    "/etc"
)

def get_confpath():
    if "--conf" in sys.argv:
        return sys.argv[sys.argv.index("--conf") + 1]
    for f in SEARCH_DIRECTORIES:
        p = format_path(f, "cdl-sconf.json")
        if os.path.isfile(p):
            return p

def format_path(direc: str, file: str):
    if direc == "/":
        return "/" + file
    else:
        return direc + "/" + file

print("cdl server v0.1")
___path = get_confpath()
print("config:", ___path)

config = json.load(open(___path, "r"))

print(f"launching on {config['host']}:{config['port']}")

enc = AESHandler(config["passcode-entry"])
dec = AESHandler(config["passcode-exit"])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((config["host"], config["port"]))
    print("socket online over tcp\n")
    while True:
        sock.listen()
        try:
            c, a = sock.accept()
            print("connection from", a)
            with c:
                d = c.recv(1024)
                if not d:
                    continue
                # challenge data
                chal = b64encode(os.urandom(config["challenge-length"])).decode("utf-8")
                msg = enc.encrypt(chal)
                # quicker to just handle this now
                # instead of decrypting the received message
                resp = dec.encrypt(chal)
                c.sendall(msg.encode())
                if resp == c.recv(1024).decode("utf-8"):
                    print(a, "succeed authentication")
                    c.sendall(b"successful authentication")
                    subprocess.Popen(shlex.split(d.decode("utf-8")))
                else:
                    print(a, "FAILED authentication")
                    c.sendall(b"failed authentication")
        except KeyboardInterrupt:
            print("\nExiting...")
            exit(0)
        except Exception as e:
            print(e)
            pass
