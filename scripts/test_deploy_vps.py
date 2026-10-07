from contextlib import closing, nullcontext
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import deploy_vps as d


def create_state(path):
    path.mkdir()
    (path / ".user_databases").mkdir()
    for name in ("shared.db", ".user_databases/mochi_owner.db@example.test.db"):
        with closing(sqlite3.connect(path / name)) as db:
            db.executescript("CREATE TABLE data(id INTEGER PRIMARY KEY, value BLOB);"
                             "INSERT INTO data VALUES(1,x'00ff');"
                             "CREATE TABLE Legacy(value TEXT); INSERT INTO Legacy VALUES('retained');")
            db.commit()


class StateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def test_complete_snapshot_preserves_legacy_tables_and_identifiers(self):
        state = self.root / "state"
        create_state(state)
        before = d.state_manifest(state)
        self.assertEqual(d.copy_state(state, self.root / "copy"), before)
        self.assertEqual(d.state_manifest(self.root / "copy"), before)
        self.assertIn(".user_databases/mochi_owner.db@example.test.db", before)

    def test_schema_row_and_added_database_changes_are_detected(self):
        state = self.root / "state"
        create_state(state)
        before = d.state_manifest(state)
        with closing(sqlite3.connect(state / "shared.db")) as db:
            db.execute("UPDATE data SET value='accepted'")
            db.commit()
        self.assertNotEqual(d.state_manifest(state), before)
        before = d.state_manifest(state)
        with closing(sqlite3.connect(state / "shared.db")) as db:
            db.execute("ALTER TABLE data ADD COLUMN extra TEXT")
            db.commit()
        self.assertNotEqual(d.state_manifest(state), before)
        before = d.state_manifest(state)
        with closing(sqlite3.connect(state / ".user_databases/mochi_new.db")) as db:
            db.execute("CREATE TABLE users(id INTEGER)")
        self.assertNotEqual(d.state_manifest(state), before)

    def test_missing_or_redirected_state_refused(self):
        state = self.root / "state"
        create_state(state)
        (state / "shared.db").unlink()
        with self.assertRaises(d.DeploymentError):
            d.state_manifest(state)
        (state / "shared.db").symlink_to("/dev/null")
        with self.assertRaises(d.DeploymentError):
            d.state_manifest(state)

    def test_archive_rejects_links_traversal_and_duplicates(self):
        for names in (("../bad",), ("/bad",), ("a", "a")):
            archive = self.root / "archive.tar"
            with tarfile.open(archive, "w") as output:
                for name in names:
                    item = tarfile.TarInfo(name)
                    item.size = 1
                    output.addfile(item, io.BytesIO(b"x"))
            destination = self.root / ("out-" + str(len(list(self.root.iterdir()))))
            destination.mkdir()
            with self.assertRaises(d.DeploymentError):
                d.extract(archive, destination)
        with tarfile.open(archive, "w") as output:
            item = tarfile.TarInfo("link")
            item.type = tarfile.SYMTYPE
            item.linkname = "/etc/passwd"
            output.addfile(item)
        with self.assertRaises(d.DeploymentError):
            d.extract(archive, self.root)

    def test_scoped_maintenance_preserves_other_routes(self):
        original = "mochi {\n reverse_proxy :4738\n}\nalias {\n reverse_proxy :4738\n}\nother {\n reverse_proxy :9000\n}\n"
        changed = d.maintenance_configuration(original)
        self.assertEqual(changed.count("503"), 2)
        self.assertIn("other {\n reverse_proxy :9000\n}", changed)
        with self.assertRaises(d.DeploymentError):
            d.maintenance_configuration(original.replace(":4738", ":4739", 1))
        with self.assertRaises(d.DeploymentError):
            d.maintenance_configuration(original + "# another 4738\n")

    def test_backup_retarget_is_exact_and_preserves_other_sources(self):
        text = (
            '[[databases]]\nlabel="mochi-shared"\npath="' + str(d.LEGACY / "shared.db") + '"\n'
            '[[databases]]\nlabel="mochi-users"\npath="' + str(d.LEGACY / ".user_databases/*.db") + '"\n'
            '[[databases]]\nlabel="other"\npath="/other.db"\n'
            '[[files]]\nlabel="mochi-configuration"\npath="' + str(d.LEGACY / ".env") + '"\n')
        unit = 'ReadWritePaths="' + str(d.LEGACY) + '" "' + str(d.LEGACY / ".user_databases") + '" "/other"\n'
        result, permissions = d.backup_configuration(text, unit)
        self.assertIn(str(d.DATA / ".user_databases/*.db"), result)
        self.assertIn('path="/other.db"', result)
        self.assertIn('"/other"', permissions)
        with self.assertRaises(d.DeploymentError):
            d.backup_configuration(text.replace("mochi-users", "wrong"), unit)

    def test_changed_process_is_never_signalled(self):
        expected = {"pid": 123, "start": "original"}
        with patch.object(d, "process_identity", return_value={"pid": 123, "start": "replacement"}), \
                patch.object(d.os, "kill") as signal:
            with self.assertRaises(d.DeploymentError):
                d.stop_exact(expected)
        signal.assert_not_called()

    def test_debugger_socket_fits_actual_private_receipt_path(self):
        receipt = Path("/root/mochi-deploy-backups/update-" + "a" * 32)
        path = d.debug_socket_path(receipt)
        self.assertEqual(path.parent, receipt)
        self.assertLess(len(os.fsencode(path)), 108)
        with self.assertRaises(d.DeploymentError):
            d.debug_socket_path(Path("/" + "a" * 108))


class FakeInstaller(d.Installer):
    def __init__(self, stage):
        super().__init__(stage)
        self.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.starts = 0
        self.accept_write = False
        self.operator_edit = False
        self.new_user = False
        self.fail_start = True
        self.calls = []

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[:2] == ["systemctl", "is-enabled"]:
            return "enabled"
        if args[:3] == ["systemctl", "start", "mochi.service"]:
            self.starts += 1
            if self.starts == 1 and self.fail_start:
                if self.accept_write:
                    with closing(sqlite3.connect(d.DATA / "shared.db")) as db:
                        db.execute("UPDATE data SET value='accepted'")
                        db.commit()
                if self.new_user:
                    with closing(sqlite3.connect(d.DATA / ".user_databases/mochi_new.db")) as db:
                        db.execute("CREATE TABLE users(id INTEGER)")
                if self.operator_edit:
                    self.backup_config.write_bytes(b"operator change")
                raise d.DeploymentError("injected start failure")
        return ""

    def stop(self):
        pass

    def permissions(self):
        pass

    def wait_health(self, *args):
        pass

    def check_process(self, release):
        if self.current.resolve() != release:
            raise d.DeploymentError("wrong current link")


class RollbackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        patcher = patch.multiple(d, ROOT=self.root / "opt", DATA=self.root / "data", ENV=self.root / "etc/mochi.env")
        patcher.start()
        self.addCleanup(patcher.stop)
        d.ROOT.mkdir()
        d.ENV.parent.mkdir()
        d.ENV.write_bytes(b"original config")
        d.ENV.chmod(0o640)
        create_state(d.DATA)
        stage = self.root / "receipt"
        stage.mkdir()
        self.installer = FakeInstaller(stage)
        self.installer.unit = self.root / "unit.service"
        self.installer.backup_config = self.root / "backup.toml"
        self.installer.backup_unit = self.root / "backup.service"
        for path in (self.installer.unit, self.installer.backup_config, self.installer.backup_unit):
            path.write_bytes(b"original")
        self.previous = d.ROOT / "releases/old"
        self.previous.mkdir(parents=True)
        (d.ROOT / "current").symlink_to(self.previous)
        self.release = d.ROOT / "releases/new"
        self.release.mkdir()
        (self.release / "mochi.service").write_bytes(b"candidate unit")
        self.before = d.state_manifest(d.DATA)

    def activate(self):
        with patch.object(d.os, "chown"):
            self.installer.activate(self.release, "a" * 40, None)

    def test_unchanged_state_allows_binary_only_rollback(self):
        with self.assertRaises(d.DeploymentError):
            self.activate()
        self.assertEqual(self.installer.current.resolve(), self.previous)
        self.assertEqual(d.state_manifest(d.DATA), self.before)
        self.assertEqual(d.ENV.read_bytes(), b"original config")
        self.assertEqual(d.ENV.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.installer.pending.exists())
        self.assertEqual(self.installer.starts, 2)

    def test_accepted_write_forbids_rollback(self):
        self.installer.accept_write = True
        with self.assertRaisesRegex(d.DeploymentError, "forbid rollback"):
            self.activate()
        self.assertEqual(self.installer.current.resolve(), self.release)
        self.assertNotEqual(d.state_manifest(d.DATA), self.before)
        self.assertTrue(self.installer.pending.exists())
        self.assertEqual(self.installer.starts, 1)

    def test_new_registration_forbids_rollback(self):
        self.installer.new_user = True
        with self.assertRaisesRegex(d.DeploymentError, "forbid rollback"):
            self.activate()
        self.assertTrue((d.DATA / ".user_databases/mochi_new.db").exists())
        self.assertTrue(self.installer.pending.exists())

    def test_operator_changes_forbid_rollback(self):
        self.installer.operator_edit = True
        with self.assertRaisesRegex(d.DeploymentError, "Operator"):
            self.activate()
        self.assertEqual(self.installer.backup_config.read_bytes(), b"operator change")
        self.assertTrue(self.installer.pending.exists())

    def test_success_preserves_exact_state_and_new_release(self):
        self.installer.fail_start = False
        self.activate()
        self.assertEqual(self.installer.current.resolve(), self.release)
        self.assertEqual(d.state_manifest(d.DATA), self.before)
        self.assertEqual(json.loads((self.installer.stage / "deployment.json").read_text())["status"], "healthy")

    def test_uncertain_shutdown_preserves_release_and_pending_receipt(self):
        with patch.object(self.installer, "stop", side_effect=d.DeploymentError("stuck shutdown")):
            with self.assertRaisesRegex(d.DeploymentError, "stuck shutdown"):
                self.activate()
        self.assertEqual(self.installer.current.resolve(), self.previous)
        self.assertEqual(d.state_manifest(d.DATA), self.before)
        self.assertTrue(self.installer.pending.exists())
        self.assertEqual(self.installer.starts, 0)

    def test_healthy_identical_release_does_not_stop_or_start(self):
        (self.release / "mochi").write_bytes(b"fixture")
        files = d.release_files(self.release)
        manifest = {"revision": "a" * 40, "architecture": platform.machine(), "files": files}
        (self.release / "release.json").write_text(json.dumps(manifest))
        release = self.release.with_name("a" * 40 + "-" + files["mochi"][:12])
        self.release.rename(release)
        self.installer.switch(release)
        self.installer.unit.write_bytes((release / "mochi.service").read_bytes())
        archive = self.installer.stage / "release.tar"
        with tarfile.open(archive, "w") as output:
            for path in release.iterdir():
                output.add(path, arcname=path.name)
        (self.installer.stage / "request.json").write_text(json.dumps({
            "migrate_tmux": False, "archive_sha256": d.checksum(archive),
        }))
        user = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir="/var/lib/mochi", pw_shell="/usr/sbin/nologin")
        with patch.object(d.os, "geteuid", return_value=0), patch.object(d.os.path, "ismount", return_value=True), \
                patch.object(d, "deployment_locks", return_value=nullcontext()), patch.object(d, "check_http"), \
                patch.object(d.pwd, "getpwnam", return_value=user), patch.object(d.os, "chown"), \
                patch.object(self.installer, "preflight") as preflight, \
                patch.object(self.installer, "stop") as stop, patch.object(d.os, "umask"):
            self.installer.install()
        preflight.assert_not_called()
        stop.assert_not_called()
        self.assertEqual(self.installer.starts, 0)
        self.assertEqual(json.loads((self.installer.stage / "deployment.json").read_text())["status"], "already_current")

    def test_initial_failure_recovers_untouched_legacy_without_stale_restore(self):
        legacy = self.root / "legacy"
        create_state(legacy)
        (legacy / ".env").write_bytes(b"original configuration")
        (legacy / "mochi").write_bytes(b"original executable")
        shutil.rmtree(d.DATA)
        d.ENV.unlink()
        self.installer.unit.unlink()
        self.installer.current.unlink()
        identity = {"pid": 123, "start": "original", "exe": str(legacy / "mochi"),
                    "cwd": str(legacy), "argv": [b"./mochi"]}
        legacy_info = {"wrapper": {"pid": 122}, "app": identity, "sha256": d.checksum(legacy / "mochi")}
        with patch.object(d, "LEGACY", legacy), patch.object(d, "stop_exact") as stop, \
                patch.object(d, "process_identity", return_value=identity), \
                patch.object(d, "inspect_legacy", return_value=True), \
                patch.object(d, "backup_configuration", return_value=("new configuration", "new unit")), \
                patch.object(d.os, "chown"):
            with self.assertRaisesRegex(d.DeploymentError, "injected start"):
                self.installer.activate(self.release, "a" * 40, legacy_info)
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(d.state_manifest(legacy), self.before)
        self.assertEqual(d.state_manifest(d.DATA), self.before)
        self.assertFalse(self.installer.current.exists())
        self.assertFalse(self.installer.pending.exists())
        self.assertTrue(any("mochi-legacy-rollback" in " ".join(call) for call in self.installer.calls))


if __name__ == "__main__":
    unittest.main()
