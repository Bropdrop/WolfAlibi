"""Transport only for the six preconfigured loopback peer links in the local fixture."""

import select
import socket
import threading


class Link:
    def __init__(self, src, dst, port):
        self.port = port
        self.lock = threading.Lock()
        self.peers = set()
        self.up = True
        self.closed = False
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((f"127.0.{src + 1}.{dst + 1}", port))
        self.listener.listen(64)
        self.listener.settimeout(0.2)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.closed:
            try:
                a, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self.forward, args=(a,), daemon=True).start()

    def forward(self, a):
        with a, socket.socket() as b:
            try:
                with self.lock:
                    if not self.up:
                        return
                    b.connect(("127.0.0.1", self.port))
                    self.peers.update((a, b))
                while True:
                    ready, _, _ = select.select((a, b), (), (), 1)
                    for src in ready:
                        data = src.recv(65536)
                        if not data:
                            return
                        (b if src is a else a).sendall(data)
            except OSError:
                pass
            finally:
                with self.lock:
                    self.peers.difference_update((a, b))

    def set(self, up):
        with self.lock:
            self.up = up
            if not up:
                for s in self.peers:
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    def close(self):
        self.closed = True
        self.set(False)
        self.listener.close()
