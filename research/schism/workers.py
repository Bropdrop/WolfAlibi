"""One isolated coordinator with 500 real threads and an external contention barrier."""

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

from research.wt_swarm.client import send_once, emit
from shirudo_adapter.model import canonical_json


def main():
    docs = json.loads(input())
    workers = 500
    wires = [canonical_json({"op": "execute", "request": r}) for r in docs]
    arrivals = threading.Barrier(workers, timeout=30)
    count = 0
    lock = threading.Lock()

    def opened():
        nonlocal count
        with lock:
            count += 1
            if count == workers:
                emit({"phase": "open", "sockets": count, "ns": time.monotonic_ns()})

    def work(i):
        tid = threading.get_native_id()
        ready = time.monotonic_ns()
        arrivals.wait()
        row = send_once(wires[i % len(docs)], opened=opened)
        row.update(worker=i, tid=tid, slot=i % len(docs), ready_ns=ready)
        return row

    threading.stack_size(512 * 1024)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        emit({"rows": list(pool.map(work, range(workers)))})


if __name__ == "__main__":
    main()
