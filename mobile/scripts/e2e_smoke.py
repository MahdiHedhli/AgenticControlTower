#!/usr/bin/env python3
"""End-to-end simulator smoke harness for the ACT mobile app.

One command:

    mobile/scripts/e2e-smoke.sh

does all of this hands-free:

  1. boot (or reuse) the iOS Simulator and enrol Face ID,
  2. start a scratch gateway built from THIS repo's ``gateway/`` on a private
     port with a throw-away SQLite database,
  3. seed the fixtures the scenarios need through the gateway's own HTTP API,
  4. run the ``integration_test`` scenarios against the simulator, answering
     the Face ID prompts as they appear,
  5. tear the gateway down and print a per-scenario pass/fail table.

Exit code is non-zero if any scenario fails.

Everything is scoped to this run: its own port (8950-8969), its own database
under a temp directory, its own node id. It never touches ~/.hermes, ports
8787/8788, ``tailscale serve``, or a physical device.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MOBILE_DIR = REPO_ROOT / "mobile"
GATEWAY_DIR = REPO_ROOT / "gateway"

DEFAULT_UDID = "97EF4CA1-2D9E-4FDB-816E-4FFF7AA6B30E"
# The gateway takes a port from this range; DEAD_PORT is deliberately left
# closed so the degradation scenarios have a guaranteed-unreachable endpoint.
PORT_RANGE = range(8950, 8969)
DEAD_PORT = 8969

# Scenario files, in the order they run. Ordering matters: app_boot leaves the
# device unpaired, and every later scenario clears device state on entry anyway.
SCENARIOS = [
    ("app_boot", "integration_test/app_boot_test.dart"),
    ("pairing", "integration_test/pairing_test.dart"),
    ("approvals", "integration_test/approvals_test.dart"),
    ("standing_grants", "integration_test/standing_grants_test.dart"),
    ("resilience", "integration_test/resilience_test.dart"),
]

APP_BUNDLE_ID = "app.act.agenticControlTower"

# Hard ceiling per scenario. macOS has no timeout(1), and a scenario CAN wedge
# beyond any in-test timeout: if the app stops producing frames (a SpringBoard
# alert in front of it, say) `tester.pump()` never returns and the test
# framework's own timeout never gets a chance to fire. Killing it here turns a
# silent stall into a reported failure.
SCENARIO_TIMEOUT_SECONDS = int(os.getenv("ACT_E2E_SCENARIO_TIMEOUT", "420"))

BIOMETRIC_MATCH = "com.apple.BiometricKit_Sim.pearl.match"
BIOMETRIC_ENROLL = "com.apple.BiometricKit_Sim.pearl.enroll"


# --------------------------------------------------------------------------
# result table
# --------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    name: str
    status: str  # passed | failed | skipped
    seconds: float
    tests_passed: int = 0
    tests_skipped: int = 0
    detail: str = ""
    output: str = field(default="", repr=False)


# --------------------------------------------------------------------------
# simulator
# --------------------------------------------------------------------------


def simctl(*args: str, check: bool = True, capture: bool = True) -> str:
    proc = subprocess.run(
        ["xcrun", "simctl", *args],
        check=False,
        capture_output=capture,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"simctl {' '.join(args)} failed ({proc.returncode}):\n"
            f"{(proc.stdout or '') + (proc.stderr or '')}"
        )
    return (proc.stdout or "") if capture else ""


def booted_udids() -> set[str]:
    raw = json.loads(simctl("list", "devices", "--json"))
    out: set[str] = set()
    for devices in raw.get("devices", {}).values():
        for device in devices:
            if device.get("state") == "Booted":
                out.add(device["udid"])
    return out


def ensure_simulator(udid: str) -> None:
    if udid in booted_udids():
        print(f"[sim] reusing booted simulator {udid}")
        return
    print(f"[sim] booting simulator {udid}")
    simctl("boot", udid)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if udid in booted_udids():
            time.sleep(3)  # let SpringBoard finish coming up
            return
        time.sleep(1)
    raise RuntimeError(f"simulator {udid} did not boot")


def kill_stale_app(udid: str) -> None:
    """A Runner left over from an interrupted run makes the next
    ``flutter test`` report "No tests ran." — it attaches to the stale process
    instead of the one it just installed. Clearing it is the difference between
    a repeatable harness and a flaky one."""
    simctl("terminate", udid, APP_BUNDLE_ID, check=False)
    subprocess.run(
        ["pkill", "-f", f"{udid}/data/Containers/Bundle/Application"],
        check=False,
        capture_output=True,
    )
    time.sleep(1)


def enroll_face_id(udid: str) -> None:
    """Mark biometry as enrolled so LAContext offers a Face ID prompt.

    ``notifyutil -s <key> 1`` sets the state and ``-p`` posts the change; the
    BiometricKit simulator shim reads exactly these two notifications. This is
    the same switch as Simulator > Features > Face ID > Enrolled.
    """
    simctl(
        "spawn", udid, "notifyutil", "-s", BIOMETRIC_ENROLL, "1", check=False
    )
    simctl("spawn", udid, "notifyutil", "-p", BIOMETRIC_ENROLL, check=False)
    print("[sim] Face ID marked enrolled")


class FaceIdAnswerer:
    """Answer Face ID prompts for the whole test run.

    The integration test runs *inside* the app process and cannot shell out, so
    the prompt has to be answered from here. Posting a match when no prompt is
    showing is a no-op, so a steady drip is both simple and safe.
    """

    def __init__(self, udid: str, interval: float = 0.4) -> None:
        self._udid = udid
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.posts = 0

    def __enter__(self) -> FaceIdAnswerer:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            subprocess.run(
                ["xcrun", "simctl", "spawn", self._udid, "notifyutil", "-p",
                 BIOMETRIC_MATCH],
                check=False,
                capture_output=True,
            )
            self.posts += 1
            self._stop.wait(self._interval)


# --------------------------------------------------------------------------
# gateway
# --------------------------------------------------------------------------


def pick_port() -> int:
    for port in PORT_RANGE:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free port in {PORT_RANGE.start}-{PORT_RANGE.stop - 1}")


def gateway_python() -> str:
    """Interpreter that can import uvicorn + the gateway's dependencies.

    Prefers this checkout's own ``gateway/.venv``, provisioning it with
    ``uv sync --frozen`` when absent, so the harness never depends on whatever
    happens to be installed in the ambient python3.
    """
    override = os.environ.get("ACT_E2E_PYTHON")
    if override:
        return override
    venv_python = GATEWAY_DIR / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)

    from shutil import which

    uv = which("uv") or str(Path.home() / ".local" / "bin" / "uv")
    if Path(uv).exists():
        print("[gateway] provisioning gateway/.venv via uv sync --frozen")
        subprocess.run(
            [uv, "sync", "--frozen"],
            cwd=str(GATEWAY_DIR),
            check=True,
            capture_output=True,
            text=True,
        )
        if venv_python.exists():
            return str(venv_python)
    return sys.executable


def start_gateway(*, port: int, database_path: Path) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env.update(
        {
            "HERMES_GATEWAY_DB": str(database_path),
            "HERMES_NODE_ID": "node_e2e",
            "HERMES_NODE_DISPLAY_NAME": "E2E Tower",
            "HERMES_NODE_FINGERPRINT": "e2e-fingerprint",
            "HERMES_GATEWAY_BASE_URL": f"http://127.0.0.1:{port}/v1",
            # Standing grants are under test; keep the feature on explicitly so
            # a changed default cannot silently turn the scenario vacuous.
            "ACT_STANDING_GRANTS_ENABLED": "1",
        }
    )
    src = str(GATEWAY_DIR / "src")
    env["PYTHONPATH"] = (
        f"{src}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src
    )
    return subprocess.Popen(
        [
            gateway_python(), "-m", "uvicorn",
            "hermes_gateway.app:create_app", "--factory",
            "--host", "127.0.0.1", "--port", str(port),
            "--log-level", "warning",
        ],
        env=env,
        cwd=str(GATEWAY_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def wait_for_gateway(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"gateway exited before becoming healthy:\n{output}")
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=3) as response:
                if json.loads(response.read())["status"] == "healthy":
                    return
        except (urllib.error.URLError, OSError, KeyError):
            time.sleep(0.25)
    raise RuntimeError("gateway did not become healthy in 30s")


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def seed_gateway(base_url: str) -> None:
    """Register this run's node. Approvals are minted by the scenarios
    themselves so that create-then-observe ordering is exact."""
    post_json(
        f"{base_url}/nodes/register",
        {
            "node_id": "node_e2e",
            "display_name": "E2E Tower",
            "environment": "homelab",
            "gateway_base_url": base_url,
            "node_fingerprint": "e2e-fingerprint",
            "gateway_version": "0.1.0",
            "hermes_version": "e2e",
            "tags": ["e2e"],
        },
    )
    print(f"[gateway] seeded node_e2e at {base_url}")


# --------------------------------------------------------------------------
# flutter
# --------------------------------------------------------------------------


def find_flutter() -> str:
    explicit = os.environ.get("FLUTTER_BIN")
    if explicit:
        return explicit
    for candidate in (
        Path.home() / "flutter" / "bin" / "flutter",
        Path("/opt/homebrew/bin/flutter"),
        Path("/usr/local/bin/flutter"),
    ):
        if candidate.exists():
            return str(candidate)
    from shutil import which

    found = which("flutter")
    if found:
        return found
    raise RuntimeError("flutter not found; set FLUTTER_BIN")


def warm_pub_cache(flutter: str) -> None:
    """Resolve dependencies once, not once per scenario."""
    subprocess.run(
        [flutter, "pub", "get"],
        cwd=str(MOBILE_DIR),
        check=False,
        capture_output=True,
        text=True,
    )


def strip_icloud_detritus() -> None:
    """``codesign`` refuses to sign anything carrying com.apple.FinderInfo, and
    the iCloud file provider stamps it back onto package directories under
    ~/Documents between builds. Clearing it is cheap; skipping it is a build
    failure that looks like a Flutter bug."""
    subprocess.run(
        ["xattr", "-cr", str(MOBILE_DIR)], check=False, capture_output=True
    )


def run_scenario(
    *,
    flutter: str,
    name: str,
    path: str,
    udid: str,
    gateway_base_url: str,
    verbose: bool,
    log_dir: Path,
) -> ScenarioResult:
    command = [
        flutter, "test", path,
        "-d", udid,
        "--dart-define", f"ACT_E2E_GATEWAY={gateway_base_url}",
        "--dart-define", f"ACT_E2E_DEAD_GATEWAY=http://127.0.0.1:{DEAD_PORT}/v1",
        "--reporter", "expanded",
    ]
    print(f"\n[run] {name}: {' '.join(command[1:])}")
    kill_stale_app(udid)

    env = os.environ.copy()
    # CoreSimulator forwards SIMCTL_CHILD_* to the launched app with the prefix
    # stripped, and flutter_tools launches through `simctl launch`. This is how
    # the app learns it is under test — see AppDelegate.registerForPushNotifications.
    env["SIMCTL_CHILD_ACT_SUPPRESS_PUSH_PROMPT"] = "1"

    started = time.monotonic()
    timed_out = False
    # Write to a real file rather than a pipe. `flutter` block-buffers into a
    # pipe, so a scenario killed on timeout came back with only its first few
    # lines — exactly the run whose tail you need.
    log_path = log_dir / f"{name}.log"
    with log_path.open("w") as log_file:
        proc = subprocess.Popen(
            command,
            cwd=str(MOBILE_DIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
        try:
            returncode = proc.wait(timeout=SCENARIO_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = -1
            proc.kill()
            proc.wait(timeout=15)
            kill_stale_app(udid)
    output = log_path.read_text(errors="replace")
    elapsed = time.monotonic() - started
    if verbose:
        print(output)

    tests_passed, tests_skipped = _tally(output)
    if timed_out:
        status = "failed"
        detail = (
            f"TIMED OUT after {SCENARIO_TIMEOUT_SECONDS}s "
            f"(last: {_last_progress(output)})"
        )
    elif returncode == 0 and tests_passed == 0 and tests_skipped:
        # Ran, but every test opted out. Never report that as green.
        status = "skipped"
        detail = _skip_reason(output) or f"{tests_skipped} skipped"
    elif returncode == 0:
        status = "passed"
        detail = f"{tests_passed} passed"
        if tests_skipped:
            detail += f", {tests_skipped} skipped ({_skip_reason(output)})"
    else:
        status = "failed"
        detail = _first_failure(output) or f"exit {returncode}"
    return ScenarioResult(
        name=name,
        status=status,
        seconds=elapsed,
        tests_passed=tests_passed,
        tests_skipped=tests_skipped,
        detail=detail,
        output=output,
    )


def _decode(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _skip_reason(output: str) -> str:
    """The reason a scenario opted out, so a skip is never silent."""
    import re

    marker = re.search(r"\[e2e\] SKIP: (.+)", output)
    if marker:
        return marker.group(1).strip()[:300]
    inline = re.search(r"\[SKIPPED: ([^\]]+)\]", output)
    if inline:
        return inline.group(1).strip()[:300]
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Skip: "):
            return stripped[len("Skip: "):].strip()[:200]
    return ""


def _last_progress(output: str) -> str:
    """The reporter's last progress line — where the run got to before it hung."""
    for line in reversed(output.splitlines()):
        if line.startswith(("00:", "01:", "02:", "03:", "04:", "05:")):
            return line.strip()[:160]
    return "no test output"


def _tally(output: str) -> tuple[int, int]:
    """Read the final `NN:NN +p -f ~s:` counters from the expanded reporter."""
    import re

    passed = skipped = 0
    for match in re.finditer(r"\+(\d+)(?:\s+-\d+)?(?:\s+~(\d+))?", output):
        passed = max(passed, int(match.group(1)))
        if match.group(2):
            skipped = max(skipped, int(match.group(2)))
    return passed, skipped


def _first_failure(output: str) -> str:
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if "[E]" in line or "Test failed. See exception logs above." in line:
            window = [
                candidate.strip()
                for candidate in lines[index : index + 8]
                if candidate.strip()
            ]
            return " / ".join(window[:3])[:300]
    return ""


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", default=os.environ.get("ACT_E2E_UDID", DEFAULT_UDID))
    parser.add_argument(
        "--scenario",
        action="append",
        help="run only these scenarios (repeatable); default is all",
    )
    parser.add_argument("--verbose", action="store_true", help="stream flutter output")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat a skipped scenario as a failure (use this in CI: a "
        "regression net that quietly stops running is worse than none)",
    )
    parser.add_argument(
        "--keep-gateway",
        action="store_true",
        help="leave the scratch gateway running for manual poking",
    )
    args = parser.parse_args()

    selected = SCENARIOS
    if args.scenario:
        wanted = set(args.scenario)
        unknown = wanted - {name for name, _ in SCENARIOS}
        if unknown:
            print(f"unknown scenario(s): {sorted(unknown)}", file=sys.stderr)
            return 2
        selected = [item for item in SCENARIOS if item[0] in wanted]

    flutter = find_flutter()
    port = pick_port()
    base_url = f"http://127.0.0.1:{port}/v1"

    print(f"[env] flutter   {flutter}")
    print(f"[env] simulator {args.udid}")
    print(f"[env] gateway   {base_url}")

    ensure_simulator(args.udid)
    kill_stale_app(args.udid)
    enroll_face_id(args.udid)
    strip_icloud_detritus()
    warm_pub_cache(flutter)

    results: list[ScenarioResult] = []
    with tempfile.TemporaryDirectory(prefix="act-e2e-") as temp_dir, FaceIdAnswerer(
        args.udid
    ):
        log_dir = Path(temp_dir) / "logs"
        log_dir.mkdir()
        for index, (name, path) in enumerate(selected):
            # A gateway per scenario, each with its own empty database. Sharing
            # one leaks fixtures between scenarios: an inbox full of a previous
            # scenario's approvals turns "the queue is empty" assertions into
            # coin flips, and makes a failure impossible to attribute.
            database_path = Path(temp_dir) / f"{name}.sqlite3"
            gateway = start_gateway(port=port, database_path=database_path)
            try:
                wait_for_gateway(base_url, gateway)
                seed_gateway(base_url)
                results.append(
                    run_scenario(
                        flutter=flutter,
                        name=name,
                        path=path,
                        udid=args.udid,
                        gateway_base_url=base_url,
                        verbose=args.verbose,
                        log_dir=log_dir,
                    )
                )
            finally:
                keep_last = args.keep_gateway and index == len(selected) - 1
                if keep_last:
                    print(f"[gateway] left running on {base_url} (pid {gateway.pid})")
                else:
                    gateway.terminate()
                    try:
                        gateway.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        gateway.kill()

    return report(results, strict=args.strict)


def report(results: list[ScenarioResult], *, strict: bool = False) -> int:
    print("\n" + "=" * 78)
    print("ACT end-to-end simulator smoke")
    print("=" * 78)
    width = max((len(item.name) for item in results), default=10)
    for item in results:
        mark = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP"}[item.status]
        print(f"  {mark}  {item.name.ljust(width)}  {item.seconds:6.1f}s  {item.detail}")
    failed = [item for item in results if item.status == "failed"]
    skipped = [item for item in results if item.status == "skipped"]
    print("-" * 78)
    total_tests = sum(item.tests_passed for item in results)
    total_skipped = sum(item.tests_skipped for item in results)
    green = len(results) - len(failed) - len(skipped)
    print(
        f"  {green}/{len(results)} scenarios green, "
        f"{len(skipped)} skipped, {len(failed)} failed "
        f"({total_tests} tests passed, {total_skipped} skipped)"
    )
    for item in skipped:
        print(f"  ! {item.name} did NOT run: {item.detail}")
    if skipped and strict:
        print("  ! --strict: skipped scenarios count as failures")
    if failed:
        print("=" * 78)
        for item in failed:
            print(f"\n--- {item.name} output (tail) ---")
            print("\n".join(item.output.splitlines()[-40:]))
    print("=" * 78)
    return 1 if failed or (strict and skipped) else 0


if __name__ == "__main__":
    raise SystemExit(main())
