# scripts/smoke_test.py
# Starts the API, calls every endpoint, then stops it.
# Run from the project root:  python scripts/smoke_test.py
import subprocess
import sys
import time

import requests

PORT = 8123
BASE = f"http://127.0.0.1:{PORT}"
results = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name} {detail}")
    results.append(bool(ok))


def wait_for_api():
    for _ in range(60):
        try:
            if requests.get(BASE + "/health", timeout=1).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


def main():
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "cloud.api:app", "--port", str(PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_api():
            raise SystemExit("FAIL  the API did not start")

        r = requests.get(BASE + "/health")
        check("GET /health", r.status_code == 200 and r.json() == {"status": "ok"})

        stats = requests.get(BASE + "/stats").json()
        check("GET /stats", stats["total_events"] > 0, f"({stats['total_events']} events)")

        logs = requests.get(BASE + "/logs", params={"outcome": "Failure", "limit": 5}).json()
        check("GET /logs (filter)",
              logs["count"] == 5 and all(e["outcome"] == "Failure" for e in logs["events"]))

        empty = requests.post(BASE + "/logs", json={"Records": []})
        check("POST /logs (empty batch)",
              empty.status_code == 200 and empty.json()["inserted"] == 0)

        d = requests.post(BASE + "/detect")
        body = d.json()
        check("POST /detect", d.status_code == 200 and body.get("alerts_raised", 0) > 0,
              f"({body.get('alerts_raised')} alerts)")

        a = requests.get(BASE + "/alerts").json()
        check("GET /alerts", a["count"] == body.get("alerts_raised"))

        crit = requests.get(BASE + "/alerts", params={"severity": "CRITICAL"}).json()
        check("GET /alerts (severity filter)",
              all(x["severity"] == "CRITICAL" for x in crit["alerts"]))

        bad = requests.post(BASE + "/detect", params={"policy": "magic"})
        check("POST /detect (bad policy rejected)", bad.status_code == 422)
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()

    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
