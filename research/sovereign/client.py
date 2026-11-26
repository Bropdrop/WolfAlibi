"""One disposable forwarding coordinator. No application signing key is mounted."""
import json
import sys
from pathlib import Path
from research.sovereign.wire import Session
from research.sovereign.cluster import tls

def main():
    msg=json.loads(sys.stdin.readline())
    ctx=tls(Path("/identity"))
    ctx.endpoint=msg["endpoint"]
    with Session(msg["port"],ctx) as session:
        if msg["lose"]:
            session.peer.sendall(json.dumps(msg["body"]).encode()+b"\n")
            print('{"sent":true}',flush=True)
            sys.stdin.readline()
        else:print(json.dumps(session.call(msg["body"])),flush=True)

if __name__=="__main__":main()
