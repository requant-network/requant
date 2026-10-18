"""Exercise the real Caddy faucet proxy without a node or testnet payments."""

import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"ip": self.headers.get("X-Real-IP")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *_):
        pass


def main():
    source = pathlib.Path(__file__).resolve().parents[1] / "deploy/faucet.Caddyfile"
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo) as upstream:
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        config = source.read_text().replace(
            "pool.requant.network", f"http://127.0.0.1:{port}"
        ).replace("127.0.0.1:19380", f"127.0.0.1:{upstream.server_port}").replace(
            "remote_ip 147.90.15.89", "remote_ip 127.0.0.2"
        )
        with tempfile.TemporaryDirectory(prefix="requant-faucet-proxy-") as tmp:
            path = pathlib.Path(tmp) / "Caddyfile"
            path.write_text("{\n admin off\n auto_https off\n}\n" + config)
            with open(pathlib.Path(tmp) / "caddy.log", "wb") as log:
                process = subprocess.Popen(
                    ["caddy", "run", "--config", str(path), "--adapter", "caddyfile"],
                    stdout=log, stderr=log,
                )
                try:
                    def request(method="GET", route="/api/faucet", client="127.0.0.1"):
                        conn = http.client.HTTPConnection(
                            "127.0.0.1", port, timeout=2, source_address=(client, 0)
                        )
                        try:
                            conn.request(method, route, headers={
                                "X-Real-IP": "198.51.100.42",
                                "X-Forwarded-For": "147.90.15.89",
                            })
                            response = conn.getresponse()
                            return response.status, dict(response.getheaders()), response.read()
                        finally:
                            conn.close()

                    for attempt in range(50):
                        try:
                            request()
                            break
                        except (ConnectionError, OSError):
                            if process.poll() is not None or attempt == 49:
                                raise
                            time.sleep(0.1)
                    for method in ("GET", "POST"):
                        status, headers, body = request(method)
                        assert status == 200 and json.loads(body)["ip"] == "127.0.0.1"
                        assert headers["X-Content-Type-Options"] == "nosniff"
                        status, _, body = request(method, client="127.0.0.2")
                        assert status == 200 and json.loads(body)["ip"] == "198.51.100.42"
                    for method, route in (("PUT", "/api/faucet"), ("GET", "/api/info"),
                                          ("GET", "/api/faucet/")):
                        assert request(method, route)[0] == 404
                    print("Faucet proxy: GET/POST, trusted IP, spoofed IP and blocked routes passed")
                finally:
                    process.terminate()
                    process.wait(timeout=5)
                    upstream.shutdown()


if __name__ == "__main__":
    main()
