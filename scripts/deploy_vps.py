"""Deploy committed Mochi releases without restoring stale application state."""

import argparse
from contextlib import closing, contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

LEGACY = Path("/mnt/volume-hel1-1/mochi")
DATA = Path("/mnt/volume-hel1-1/mochi-state")
ENV = Path("/etc/mochi/mochi.env")
ROOT = Path("/opt/mochi")
PUBLIC = "https://mochi.meadow.cafe"
TOOLCHAIN = "go1.25.6"


class DeploymentError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def checksum(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_write(path, contents):
    binary = isinstance(contents, bytes)
    fd, name = tempfile.mkstemp(prefix=".install-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb" if binary else "w") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def extract(archive, destination):
    seen = set()
    with tarfile.open(archive) as source:
        for member in source:
            path = PurePosixPath(member.name)
            require(path.parts and not path.is_absolute() and ".." not in path.parts
                    and path.as_posix() not in seen and (member.isfile() or member.isdir()),
                    "Unsafe archive member")
            seen.add(path.as_posix())
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            else:
                with source.extractfile(member) as incoming, target.open("xb") as output:
                    shutil.copyfileobj(incoming, output)


def release_files(directory):
    result = {}
    for path in [directory, *directory.rglob("*")]:
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "Redirected release")
        if path.is_file() and path != directory / "release.json":
            result[path.relative_to(directory).as_posix()] = checksum(path)
    return result


def database_digest(db):
    require(db.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "SQLite integrity failed")
    db.text_factory = bytes
    digest = hashlib.sha256()
    try:
        digest.update(repr(db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()).encode("ascii"))
        for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
            table = '"' + name.decode().replace('"', '""') + '"'
            primary = sorted((row[5], row[1]) for row in db.execute("PRAGMA table_info(" + table + ")") if row[5])
            order = ",".join('"' + column.decode().replace('"', '""') + '"' for _, column in primary) or "rowid"
            digest.update(name)
            for row in db.execute("SELECT * FROM " + table + " ORDER BY " + order):
                digest.update(repr(row).encode("ascii"))
        for pragma in ("user_version", "application_id"):
            digest.update(repr(db.execute("PRAGMA " + pragma).fetchone()).encode("ascii"))
    finally:
        db.text_factory = str
    return digest.hexdigest()


def database_paths(state):
    folder = state / ".user_databases"
    require(state.is_dir() and not state.is_symlink() and folder.is_dir() and not folder.is_symlink(),
            "State directory missing or redirected")
    paths = [state / "shared.db", *sorted(folder.glob("*.db"))]
    require(all(path.is_file() and not path.is_symlink() for path in paths),
            "Database missing or redirected")
    require(all(path.name.startswith("mochi_") for path in paths[1:]), "Unexpected user database filename")
    return paths


def state_manifest(state):
    result = {}
    for path in database_paths(state):
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            result[path.relative_to(state).as_posix()] = database_digest(db)
    return result


def copy_state(source, destination):
    destination.mkdir(mode=0o700)
    (destination / ".user_databases").mkdir(mode=0o700)
    result = {}
    for path in database_paths(source):
        target = destination / path.relative_to(source)
        deadline = time.monotonic() + 120

        def progress(*_):
            require(time.monotonic() < deadline, "SQLite snapshot exceeded its deadline")

        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as incoming:
            with closing(sqlite3.connect(target)) as output:
                incoming.backup(output, pages=256, progress=progress, sleep=0.05)
                result[path.relative_to(source).as_posix()] = database_digest(output)
        target.chmod(0o600)
        with target.open("rb") as output:
            os.fsync(output.fileno())
    for path in (destination / ".user_databases", destination):
        sync_directory(path)
    return result


def backup_configuration(text, unit):
    expected = copy.deepcopy(tomllib.loads(text))
    for section, label, old, new in (
        ("databases", "mochi-shared", str(LEGACY / "shared.db"), str(DATA / "shared.db")),
        ("databases", "mochi-users", str(LEGACY / ".user_databases/*.db"), str(DATA / ".user_databases/*.db")),
        ("files", "mochi-configuration", str(LEGACY / ".env"), str(ENV)),
    ):
        entries = [item for item in expected[section] if item.get("label") == label]
        require(len(entries) == 1 and entries[0]["path"] == old and text.count(json.dumps(old)) == 1,
                "Backup sources differ from reviewed Mochi coverage")
        require(not any(item["path"] == new for item in expected[section]), "Duplicate backup source")
        entries[0]["path"] = new
        text = text.replace(json.dumps(old), json.dumps(new), 1)
    require(tomllib.loads(text) == expected, "Unexpected backup configuration change")
    lines = re.findall(r"(?m)^ReadWritePaths=(.*)$", unit)
    require(len(lines) == 1, "Unexpected backup unit permissions")
    for old, new in ((LEGACY, DATA), (LEGACY / ".user_databases", DATA / ".user_databases")):
        require(shlex.split(lines[0]).count(str(old)) == 1 and unit.count(json.dumps(str(old))) == 1,
                "Backup SQLite parent permissions differ")
        unit = unit.replace(json.dumps(str(old)), json.dumps(str(new)), 1)
    return text, unit


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def request(url):
    req = Request(url, headers={"User-Agent": "MochiDeploymentCheck/1.0"})
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(req, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(4 * 1024**2 + 1)
        require(len(body) <= 4 * 1024**2, "Oversized deployment response")
        return response.status, body


def health(origin, revision, workers, users=None):
    code, body = request(origin + "/healthz")
    require(code == 200, "Health endpoint unavailable")
    value = json.loads(body)
    require(value.get("status") == "ok" and value.get("revision") == revision
            and value.get("workers") is workers and type(value.get("userDatabases")) is int,
            "Health revision/mode mismatch")
    require(users is None or value["userDatabases"] == users, "User database inventory mismatch")


def check_http(origin):
    for path in ("/", "/user/login", "/user/register"):
        code, body = request(origin + path)
        require(code == 200 and b"<html" in body.lower(), "Mochi page check failed")


def process_identity(pid):
    require(type(pid) is int and pid > 1, "Invalid process ID")
    path = Path("/proc") / str(pid)
    stat = (path / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "parent": int(stat[1]), "start": stat[19],
            "exe": os.readlink(path / "exe"), "cwd": os.readlink(path / "cwd"),
            "argv": (path / "cmdline").read_bytes().split(b"\0")[:-1]}


def stop_exact(expected):
    require(process_identity(expected["pid"]) == expected, "Process changed before signal")
    os.kill(expected["pid"], signal.SIGTERM)
    deadline = time.monotonic() + 30
    while Path("/proc", str(expected["pid"])).exists():
        try:
            stat = Path("/proc", str(expected["pid"]), "stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return
        require(stat[19] == expected["start"], "Process ID reused")
        if stat[0] == "Z":
            return
        require(time.monotonic() < deadline, "Legacy shutdown unconfirmed; no forced kill")
        time.sleep(0.1)


def inspect_legacy(expected, receipt):
    """Read stack names only, then explicitly detach without killing the target."""
    require(process_identity(expected["pid"]) == expected, "Legacy process changed")
    status_path = Path("/proc", str(expected["pid"]), "status")
    initial_status = status_path.read_text()
    require("TracerPid:\t0\n" in initial_status and not re.search(r"(?m)^State:\s+[tT]", initial_status),
            "Legacy process was already stopped/traced")
    tool = Path("/root/mochi-deploy-backups/tools/dlv")
    require(tool.is_file(), "Install reviewed Delve 1.25.2 before legacy cutover")
    path = receipt / ("debug-" + uuid.uuid4().hex + ".sock")
    with (receipt / "goroutines.private.log").open("ab") as output:
        debugger = subprocess.Popen([str(tool), "attach", str(expected["pid"]), "--headless",
                                     "--api-version=2", "--listen=unix:" + str(path)],
                                    stdout=output, stderr=output)
        connection = None
        stream = None
        detached = False
        try:
            deadline = time.monotonic() + 20
            while not path.exists():
                require(debugger.poll() is None and time.monotonic() < deadline,
                        "Debugger did not become ready")
                time.sleep(0.02)
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(10)
            connection.connect(str(path))
            stream = connection.makefile("rwb")
            counter = 0

            def call(method, value):
                nonlocal counter
                counter += 1
                stream.write((json.dumps({"method": "RPCServer." + method, "params": [value], "id": counter}) + "\n").encode())
                stream.flush()
                response = json.loads(stream.readline())
                require(response.get("error") is None, "Debugger stack inspection failed")
                return response["result"]

            names = []
            offset = 0
            while True:
                result = call("ListGoroutines", {"Start": offset, "Count": 100})
                for item in result["Goroutines"]:
                    stack = call("Stacktrace", {"Id": item["id"], "Depth": 80, "Full": False, "Opts": 0})
                    for frame in stack["Locations"]:
                        function = frame.get("function")
                        if function:
                            names.append(function["name"])
                offset = result["Nextg"]
                if offset < 0:
                    break
                require(offset < 10000, "Unexpected goroutine inventory size")
            private_write(receipt / "stack-functions.private.json", json.dumps(names))
            busy = (
                "site.ReaperPostHit.func", "site.WebmentionReceive.func", "notifier.StartInteractionHandler.func2",
                "notifier.SendMessageToUsername", "notifier.CheckAndSendScheduledMetricsReports",
                "main.cleanupOldData", "user_database.cleanupCache", "webmention_sender.CheckAllMonitoredURLs",
                "webmention_sender.ProcessFeed", "webmention_sender.ProcessSingleURL",
            )
            idle = not any(name.removeprefix("mochi/").startswith(busy) for name in names)
            call("Detach", {"Kill": False})
            detached = True
            return idle
        finally:
            try:
                if stream and not detached:
                    stream.write(b'{"method":"RPCServer.Detach","params":[{"Kill":false}],"id":99999}\n')
                    stream.flush()
                    response = json.loads(stream.readline())
                    require(response.get("error") is None, "Explicit debugger detach failed; inspect original process")
            finally:
                try:
                    if stream:
                        stream.close()
                finally:
                    if connection:
                        connection.close()
                    if debugger.poll() is None:
                        debugger.send_signal(signal.SIGINT)
                        debugger.wait(timeout=20)
                    path.unlink(missing_ok=True)
                    require(process_identity(expected["pid"]) == expected, "Legacy identity changed during inspection")
                    status = status_path.read_text()
                    require("TracerPid:\t0\n" in status, "Legacy debugger remains attached")
                    if re.search(r"(?m)^State:\s+T", status):
                        require(process_identity(expected["pid"]) == expected, "Legacy process changed before resume")
                        os.kill(expected["pid"], signal.SIGCONT)
                        deadline = time.monotonic() + 2
                        while re.search(r"(?m)^State:\s+[tT]", status_path.read_text()):
                            require(time.monotonic() < deadline, "Legacy process did not resume")
                            time.sleep(0.02)
                        status = status_path.read_text()
                    require("TracerPid:\t0\n" in status and not re.search(r"(?m)^State:\s+[tT]", status),
                            "Legacy target has not resumed after debugger detach")


def maintenance_configuration(text):
    pattern = r"(?m)^([ \t]*)reverse_proxy :4738[ \t]*$"
    require(len(re.findall(pattern, text)) == 2, "Mochi proxy differs from reviewed routes")
    result = re.sub(pattern, lambda match: match[1] + 'respond "Mochi is temporarily down for maintenance." 503', text)
    require("4738" not in result, "Another route still reaches old Mochi")
    return result


@contextmanager
def deployment_locks():
    with Path("/var/lib/backuper/job.lock").open("rb") as backup, (ROOT / ".deploy.lock").open("a") as application:
        fcntl.flock(backup, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(application, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


class Installer:
    def __init__(self, stage):
        self.stage = stage
        self.pending = ROOT / "deployment-pending.json"
        self.current = ROOT / "current"
        self.unit = Path("/etc/systemd/system/mochi.service")
        self.backup_config = Path("/etc/backuper/config.toml")
        self.backup_unit = Path("/etc/systemd/system/backuper.service")
        self.caddy = Path("/etc/caddy/Caddyfile")

    def run(self, arguments, timeout=180, check=True):
        with (self.stage / "install.private.log").open("ab") as log:
            result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=log, timeout=timeout)
            if result.returncode and check:
                log.write(result.stdout)
                raise DeploymentError("Command failed; inspect private receipt")
        return result.stdout.decode().strip()

    def record(self, status, **values):
        path = self.stage / "deployment.json"
        result = json.loads(path.read_text()) if path.exists() else {}
        result.update(status=status, **values)
        private_write(path, json.dumps(result, indent=2) + "\n")

    def switch(self, release):
        link = ROOT / (".current-" + uuid.uuid4().hex)
        link.symlink_to(release)
        link.replace(self.current)
        sync_directory(ROOT)

    def stop(self):
        self.run(["systemctl", "stop", "mochi.service"], timeout=680)
        require(self.run(["systemctl", "show", "mochi.service", "-p", "MainPID", "--value"]) == "0",
                "Managed shutdown unconfirmed; preserving state")

    def permissions(self):
        for path in [DATA, *DATA.rglob("*")]:
            require(not path.is_symlink() and (path.is_file() or path.is_dir()), "State path redirected")
            os.chown(path, self.user.pw_uid, self.user.pw_gid)
            path.chmod(0o700 if path.is_dir() else 0o600)

    def wait_health(self, origin, revision, workers, users):
        deadline = time.monotonic() + 30
        while True:
            try:
                health(origin, revision, workers, users)
                return
            except (URLError, TimeoutError, DeploymentError):
                require(time.monotonic() < deadline, "Mochi did not become healthy")
                time.sleep(0.2)

    def check_process(self, release):
        require(self.run(["systemctl", "is-active", "mochi.service"]) == "active", "Mochi inactive")
        pid = int(self.run(["systemctl", "show", "mochi.service", "-p", "MainPID", "--value"]))
        require(Path("/proc", str(pid), "exe").resolve() == release / "mochi"
                and Path("/proc", str(pid)).stat().st_uid == self.user.pw_uid, "Unexpected executable/user")
        listeners = self.run(["ss", "-ltnp", "sport = :4738"])
        require("127.0.0.1:4738" in listeners and f"pid={pid}," in listeners
                and "*:4738" not in listeners and "[::]:4738" not in listeners, "Unexpected listener")
        health("http://127.0.0.1:4738", json.loads((release / "release.json").read_text())["revision"], True)

    @contextmanager
    def maintenance(self, legacy):
        original = self.caddy.read_bytes()
        candidate = maintenance_configuration(original.decode()).encode()
        mode = self.caddy.stat().st_mode & 0o777
        adapted = json.loads(self.run(["caddy", "adapt", "--config", str(self.caddy), "--adapter", "caddyfile"]))
        code, live = request("http://127.0.0.1:2019/config/")
        require(code == 200 and json.loads(live) == adapted, "Caddy live/disk mismatch")
        private_write(self.stage / "Caddyfile.before", original)
        private_write(self.stage / "Caddyfile.maintenance", candidate)
        self.run(["caddy", "validate", "--config", str(self.stage / "Caddyfile.maintenance"), "--adapter", "caddyfile"])
        try:
            require(self.caddy.read_bytes() == original, "Caddy changed before maintenance")
            private_write(self.caddy, candidate)
            self.caddy.chmod(mode)
            self.run(["caddy", "reload", "--config", str(self.caddy), "--adapter", "caddyfile"])
            self.record("maintenance")
            if legacy:
                deadline = time.monotonic() + 360
                while self.run(["ss", "-Hnt", "state", "established", "sport = :4738"]) or not inspect_legacy(legacy["app"], self.stage):
                    require(time.monotonic() < deadline, "Legacy accepted work did not drain; keeping old app")
                    time.sleep(1)
            yield
        finally:
            require(self.caddy.read_bytes() in (original, candidate), "Operator edited Caddy; restore Mochi routes manually")
            private_write(self.caddy, original)
            self.caddy.chmod(mode)
            self.run(["caddy", "reload", "--config", str(self.caddy), "--adapter", "caddyfile"])
            code, live = request("http://127.0.0.1:2019/config/")
            require(code == 200 and json.loads(live) == adapted, "Caddy restoration mismatch")

    def preflight(self, release, revision, source, configuration):
        parent = Path("/var/lib/mochi-deploy-checks")
        parent.mkdir(mode=0o711, exist_ok=True)
        parent.chmod(0o711)
        trial = Path(tempfile.mkdtemp(prefix="check-", dir=parent))
        trial.chmod(0o700)
        name = "mochi-check-" + uuid.uuid4().hex
        started = False
        try:
            before = copy_state(source, trial / "state")
            private_write(trial / "mochi.env", configuration)
            for path in [trial, *trial.rglob("*")]:
                os.chown(path, self.user.pw_uid, self.user.pw_gid)
                path.chmod(0o700 if path.is_dir() else 0o600)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            settings = {
                "MOCHI_STATE_DIR": str(trial / "state"), "MOCHI_ENV_FILE": str(trial / "mochi.env"),
                "MOCHI_HTTP_ADDR": "127.0.0.1:" + str(port), "MOCHI_REQUIRE_EXISTING": "1",
                "MOCHI_AUTO_MIGRATE": "disabled", "MOCHI_WORKERS": "disabled",
            }
            self.run(["systemd-run", "--quiet", "--unit=" + name, "-p", "Type=exec", "-p", "User=mochi",
                      "-p", "Group=mochi", "-p", "UMask=0077", "-p", "WorkingDirectory=" + str(release),
                      "-p", "Environment=" + " ".join(key + "=" + value for key, value in settings.items()),
                      "-p", "ProtectSystem=strict", "-p", "ProtectHome=true", "-p", "PrivateTmp=true",
                      "-p", "PrivateDevices=true", "-p", "NoNewPrivileges=true", "-p", "ReadWritePaths=" + str(trial),
                      "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=localhost",
                      "-p", "TimeoutStopSec=660", "-p", "SendSIGKILL=no",
                      "-p", "StandardOutput=append:" + str(self.stage / "preflight.private.log"),
                      "-p", "StandardError=append:" + str(self.stage / "preflight.private.log"), str(release / "mochi")])
            started = True
            self.wait_health("http://127.0.0.1:" + str(port), revision, False, len(before) - 1)
            check_http("http://127.0.0.1:" + str(port))
            self.run(["systemctl", "stop", name], timeout=680)
            started = False
            require(state_manifest(trial / "state") == before, "Copied startup changed schema/data; review migration")
            self.record("preflight_passed", preflight_manifest=before)
        finally:
            if started:
                self.run(["systemctl", "stop", name], timeout=680)
            shutil.rmtree(trial)

    def activate(self, release, revision, legacy):
        initial = legacy is not None
        previous = None if initial else self.current.resolve()
        watched = (ENV, self.unit, self.backup_config, self.backup_unit, *((LEGACY / ".env",) if initial else ()))
        before = {path: path.read_bytes() if path.exists() else None for path in watched}
        attributes = {path: (path.stat().st_mode & 0o777, path.stat().st_uid, path.stat().st_gid)
                      for path in watched if path.exists()}
        changed = {}
        state_before = None
        legacy_stopped = False
        private_write(self.stage / "transaction.json", json.dumps({
            "initial": initial, "previous": str(previous) if previous else None,
            "files_before": {str(path): value.decode() if value is not None else None for path, value in before.items()},
        }, indent=2))
        private_write(self.pending, json.dumps({"receipt": str(self.stage), "release": str(release), "initial": initial}))
        try:
            if initial:
                stop_exact(legacy["wrapper"])
                identity = process_identity(legacy["app"]["pid"])
                require(all(identity[key] == legacy["app"][key] for key in ("pid", "start", "exe", "cwd", "argv")),
                        "Legacy app changed after wrapper stop")
                require(inspect_legacy(identity, self.stage), "Legacy background work resumed; preserve app")
                stop_exact(identity)
                legacy_stopped = True
                state_before = copy_state(LEGACY, self.stage / "state.before")
                require(not DATA.exists(), "Managed state appeared concurrently")
                copy_state(self.stage / "state.before", DATA)
                changed[ENV] = (LEGACY / ".env").read_bytes()
                require(changed[ENV] == before[LEGACY / ".env"], "Legacy configuration changed during shutdown")
                config, unit = backup_configuration(before[self.backup_config].decode(), before[self.backup_unit].decode())
                changed[self.backup_config], changed[self.backup_unit] = config.encode(), unit.encode()
            else:
                self.stop()
                state_before = copy_state(DATA, self.stage / "state.before")
            require(state_manifest(DATA) == state_before, "Relocated state differs")
            self.record("backed_up", state_manifest=state_before)
            changed[self.unit] = (release / "mochi.service").read_bytes()
            for path, value in changed.items():
                require((path.read_bytes() if path.exists() else None) == before[path], "Operator configuration changed")
                private_write(path, value)
                path.chmod(0o644 if path in (self.unit, self.backup_unit) else 0o600)
            ENV.chmod(0o640)
            os.chown(ENV, 0, self.user.pw_gid)
            self.permissions()
            self.switch(release)
            self.run(["systemctl", "daemon-reload"])
            self.run(["systemd-analyze", "verify", str(self.unit)])
            self.run(["systemctl", "start", "mochi.service"])
            self.wait_health("http://127.0.0.1:4738", revision, True, len(state_before) - 1)
            self.check_process(release)
            require(state_manifest(DATA) == state_before, "State changed during startup verification")
            self.run(["systemctl", "enable", "mochi.service"])
            self.record("healthy", revision=revision, release=str(release), relocation_verified=initial)
        except BaseException:
            self.record("needs_recovery")
            if initial and not legacy_stopped:
                raise DeploymentError("Legacy shutdown unconfirmed; preserve app and inspect pending receipt") from None
            self.stop()
            if state_before is None or state_manifest(DATA) != state_before:
                self.run(["systemctl", "disable", "mochi.service"])
                raise DeploymentError("Accepted writes/schema changes forbid rollback; no stale state restored") from None
            require(all((path.read_bytes() if path.exists() else None) in (value, changed.get(path, value))
                        for path, value in before.items()), "Operator changes forbid rollback")
            for path in changed:
                if before[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    private_write(path, before[path])
                    mode, owner, group = attributes[path]
                    path.chmod(mode)
                    os.chown(path, owner, group)
            self.run(["systemctl", "daemon-reload"])
            if previous:
                self.switch(previous)
                self.run(["systemctl", "start", "mochi.service"])
                self.check_process(previous)
            else:
                require(state_manifest(LEGACY) == state_before and checksum(LEGACY / "mochi") == legacy["sha256"],
                        "Legacy state/artifact changed; manual recovery required")
                if self.current.is_symlink():
                    self.current.unlink()
                self.run(["systemd-run", "--quiet", "--unit=mochi-legacy-rollback", "-p", "Type=exec",
                          "-p", "WorkingDirectory=" + str(LEGACY), str(LEGACY / "mochi")])
            self.record("rolled_back")
            self.pending.unlink()
            raise

    def install(self):
        require(os.geteuid() == 0 and os.path.ismount("/mnt/volume-hel1-1"), "Root and mounted data volume required")
        os.umask(0o077)
        require(not ROOT.is_symlink() and not DATA.is_symlink() and not ENV.parent.is_symlink(),
                "Managed path redirected")
        ROOT.mkdir(mode=0o755, exist_ok=True)
        ROOT.chmod(0o755)
        with deployment_locks():
            require(not self.pending.exists(), "Pending deployment requires recovery")
            metadata = json.loads((self.stage / "request.json").read_text())
            initial = metadata["migrate_tmux"]
            require(initial == (not self.current.exists()), "Migration/update mode differs from layout")
            legacy = None
            if initial:
                require(not any(path.exists() or path.is_symlink() for path in (DATA, ENV, self.unit, self.current)),
                        "Partial managed layout requires review")
                app = process_identity(metadata["legacy_pid"])
                wrapper = process_identity(metadata["wrapper_pid"])
                require(app["exe"] == str(LEGACY / "mochi") and app["cwd"] == str(LEGACY)
                        and app["argv"] == [b"./mochi"] and app["parent"] == wrapper["pid"]
                        and wrapper["cwd"] == str(LEGACY) and wrapper["argv"] == [b"bash", b"run_forever.sh"],
                        "Legacy identities differ")
                require(checksum(Path("/proc", str(app["pid"]), "exe")) == metadata["legacy_sha256"], "Legacy binary changed")
                legacy = {"app": app, "wrapper": wrapper, "sha256": metadata["legacy_sha256"]}
                source, configuration = LEGACY, (LEGACY / ".env").read_bytes()
                backup_configuration(self.backup_config.read_text(), self.backup_unit.read_text())
            else:
                require(self.current.is_symlink() and self.current.resolve().parent == ROOT / "releases",
                        "Unknown current release")
                require(self.unit.read_bytes() == (self.current / "mochi.service").read_bytes()
                        and not self.run(["systemctl", "show", "mochi.service", "-p", "DropInPaths", "--value"]),
                        "Unit has operator changes")
                source, configuration = DATA, ENV.read_bytes()
            size = sum(path.stat().st_size for path in database_paths(source))
            require(shutil.disk_usage(ROOT).free > size * 3 + 512 * 1024**2
                    and shutil.disk_usage(DATA.parent).free > size * 2 + 256 * 1024**2, "Insufficient snapshot capacity")
            require(checksum(self.stage / "release.tar") == metadata["archive_sha256"], "Upload checksum mismatch")
            unpacked = self.stage / "unpacked"
            unpacked.mkdir()
            extract(self.stage / "release.tar", unpacked)
            manifest = json.loads((unpacked / "release.json").read_text())
            files = release_files(unpacked)
            revision = manifest["revision"]
            require(re.fullmatch("[0-9a-f]{40}", revision) and manifest["architecture"] == platform.machine()
                    and files == manifest["files"] and {"mochi", "mochi.service"} <= files.keys()
                    and all(name in ("mochi", "mochi.service") or name.startswith(("assets/", "templates/")) for name in files),
                    "Release manifest mismatch")
            releases = ROOT / "releases"
            require(not releases.is_symlink(), "Release parent redirected")
            releases.mkdir(mode=0o755, exist_ok=True)
            releases.chmod(0o755)
            release = releases / (revision + "-" + files["mochi"][:12])
            if release.exists():
                require(release_files(release) == files
                        and (release / "release.json").read_bytes() == (unpacked / "release.json").read_bytes(),
                        "Existing release differs")
            else:
                shutil.copytree(unpacked, release)
            for path in [release, *release.rglob("*")]:
                path.chmod(0o755 if path.is_dir() or path == release / "mochi" else 0o644)
                if path.is_file():
                    with path.open("rb") as file:
                        os.fsync(file.fileno())
            sync_directory(release)
            sync_directory(releases)
            try:
                self.user = pwd.getpwnam("mochi")
            except KeyError:
                self.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/var/lib/mochi",
                          "--shell", "/usr/sbin/nologin", "mochi"])
                self.user = pwd.getpwnam("mochi")
            require(self.user.pw_uid != 0 and self.user.pw_dir == "/var/lib/mochi"
                    and self.user.pw_shell == "/usr/sbin/nologin", "Unexpected service account")
            ENV.parent.mkdir(mode=0o750, exist_ok=True)
            ENV.parent.chmod(0o750)
            os.chown(ENV.parent, 0, self.user.pw_gid)
            check_http(PUBLIC)
            if not initial and self.current.resolve() == release:
                self.check_process(release)
                require(self.run(["systemctl", "is-enabled", "mochi.service"]) == "enabled", "Service not enabled")
                self.record("already_current", revision=revision, release=str(release))
                return
            watched = (self.unit, ENV, self.backup_config, self.backup_unit, *((LEGACY / ".env",) if initial else ()))
            expected = {path: path.read_bytes() if path.exists() else None for path in watched}
            self.preflight(release, revision, source, configuration)
            require(all((path.read_bytes() if path.exists() else None) == value for path, value in expected.items()),
                    "Configuration changed during rehearsal")
            if metadata.get("rehearse"):
                self.record("rehearsal_complete", revision=revision, release=str(release))
                return
            with self.maintenance(legacy):
                require(all((path.read_bytes() if path.exists() else None) == value for path, value in expected.items()),
                        "Configuration changed before cutover")
                self.activate(release, revision, legacy)
            health(PUBLIC, revision, True)
            check_http(PUBLIC)
            self.record("verified_public")
            private_write(ROOT / "deployed.json", (self.stage / "deployment.json").read_text())
            self.pending.unlink()


def ssh(host, arguments):
    subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
                    "-o", "ServerAliveCountMax=3", host, shlex.join(arguments)], check=True)


def deploy(args):
    require(re.fullmatch("[A-Za-z0-9_][A-Za-z0-9_.@-]*", args.host), "Invalid SSH host")
    require(not args.migrate_tmux or (args.legacy_pid and args.wrapper_pid and args.legacy_sha256
            and re.fullmatch("[0-9a-f]{64}", args.legacy_sha256)), "Migration needs exact verified PIDs/binary hash")
    repository = Path(__file__).resolve().parents[1]

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()

    require(not git("status", "--porcelain", "--untracked-files=no"), "Commit intended changes before deployment")
    revision = git("rev-parse", "HEAD")
    require(args.yes, "Pass --yes after reviewing the deployment")
    with tempfile.TemporaryDirectory(prefix="mochi-deploy-") as directory:
        directory = Path(directory)
        source = directory / "source"
        source.mkdir()
        subprocess.run(["git", "-C", str(repository), "archive", "-o", str(directory / "source.tar"), revision], check=True)
        extract(directory / "source.tar", source)
        environment = {**os.environ, "GOTOOLCHAIN": TOOLCHAIN, "CGO_ENABLED": "1", "CC": "/usr/bin/gcc"}
        require(subprocess.check_output(["go", "version"], env=environment, text=True).strip()
                == "go version go1.25.6 linux/amd64", "Use the reviewed native Go1.25.6 toolchain")
        for tags in ("", "release"):
            subprocess.run(["go", "test", "-mod=readonly", "-race", "-tags", tags, "-count=1", "-timeout", "5m", "./..."],
                           cwd=source, env=environment, check=True)
        subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_deploy*.py"],
                       cwd=source, check=True)
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Native Linux amd64 build required")
        require(git("rev-parse", "HEAD") == revision and not git("status", "--porcelain", "--untracked-files=no"),
                "Source changed during validation")
        payload = directory / "payload"
        payload.mkdir()
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", "release",
                        "-ldflags", "-X main.buildRevision=" + revision, "-o", str(payload / "mochi"), "."],
                       cwd=source, env=environment, check=True)
        for name in ("assets", "templates"):
            shutil.copytree(source / name, payload / name)
        shutil.copyfile(source / "deploy/mochi.service", payload / "mochi.service")
        private_write(payload / "release.json", json.dumps({
            "revision": revision, "architecture": platform.machine(), "files": release_files(payload)}))
        archive = directory / "release.tar"
        with tarfile.open(archive, "w") as output:
            for path in sorted(payload.iterdir()):
                output.add(path, arcname=path.name)
        metadata = {"archive_sha256": checksum(archive), "migrate_tmux": args.migrate_tmux, "rehearse": args.rehearse,
                    "legacy_pid": args.legacy_pid, "wrapper_pid": args.wrapper_pid, "legacy_sha256": args.legacy_sha256}
        private_write(directory / "request.json", json.dumps(metadata))
        identifier = uuid.uuid4().hex
        stage = "/root/mochi-deploy-backups/update-" + identifier
        ssh(args.host, ["install", "-d", "-m", "0700", stage])
        print("Private deployment receipt: " + stage, flush=True)
        subprocess.run(["scp", "-q", str(archive), str(directory / "request.json"), str(directory / "source.tar"),
                        str(source / "scripts/deploy_vps.py"), args.host + ":" + stage + "/"], check=True)
        ssh(args.host, ["systemd-run", "--quiet", "--wait", "--unit=mochi-deploy-" + identifier, "-p", "Type=oneshot",
                        "-p", "TimeoutStartSec=infinity", "-p", "UMask=0077",
                        "-p", "StandardOutput=append:" + stage + "/install.private.log",
                        "-p", "StandardError=append:" + stage + "/install.private.log",
                        "/usr/bin/python3", "-B", stage + "/deploy_vps.py", "--install", stage])
        print("Mochi operation completed; inspect " + stage + "/deployment.json", flush=True)


def main():
    if sys.argv[1:2] == ["--install"]:
        require(len(sys.argv) == 3 and re.fullmatch("/root/mochi-deploy-backups/update-[0-9a-f]{32}", sys.argv[2]),
                "Invalid receipt")
        installer = Installer(Path(sys.argv[2]))
        try:
            installer.install()
        except BaseException:
            path = installer.stage / "deployment.json"
            previous = json.loads(path.read_text()) if path.exists() else {}
            if previous.get("status") != "rolled_back":
                installer.record("needs_recovery" if installer.pending.exists() else "failed",
                                 last_phase=previous.get("status"))
            raise
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="meadow-ubuntu-8gb-hel1-1")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--migrate-tmux", action="store_true")
    parser.add_argument("--legacy-pid", type=int)
    parser.add_argument("--wrapper-pid", type=int)
    parser.add_argument("--legacy-sha256")
    parser.add_argument("--rehearse", action="store_true")
    deploy(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, DeploymentError) else type(error).__name__
        print("Deployment failed: " + message + "; inspect private receipt before retrying", file=sys.stderr)
        raise SystemExit(1)
