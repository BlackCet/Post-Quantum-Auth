import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil


class ProxyMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._peak_memory = 0
        self._stop = threading.Event()
        threading.Thread(target=self._sample_loop, daemon=True).start()

    def _sample_loop(self):
        while not self._stop.wait(0.05):
            self.snapshot()

    def snapshot(self):
        root = psutil.Process()
        processes = [root, *root.children(recursive=True)]
        cpu_seconds = 0.0
        memory_bytes = 0
        for process in processes:
            try:
                cpu = process.cpu_times()
                cpu_seconds += cpu.user + cpu.system
                memory_bytes += process.memory_info().rss
            except psutil.Error:
                continue

        with self._lock:
            self._peak_memory = max(self._peak_memory, memory_bytes)
            return {
                "cpu_time_ms": round(cpu_seconds * 1000, 3),
                "memory_rss_bytes": memory_bytes,
                "peak_memory_rss_bytes": self._peak_memory,
            }


class MetricsHandler(BaseHTTPRequestHandler):
    metrics = None

    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = json.dumps(self.metrics.snapshot()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def monitor_nginx(server, process):
    while process.poll() is None:
        time.sleep(0.25)
    server.shutdown()


def main():
    import subprocess

    process = subprocess.Popen(["nginx", "-g", "daemon off;"])
    MetricsHandler.metrics = ProxyMetrics()
    server = ThreadingHTTPServer(("0.0.0.0", 9100), MetricsHandler)
    threading.Thread(
        target=monitor_nginx,
        args=(server, process),
        daemon=True,
    ).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
    if process.returncode:
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()
