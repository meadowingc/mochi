# Managed Mochi runtime

The runtime now stops HTTP acceptance, closes Discord ingress, joins scheduled
work and drains accepted analytics, webmentions and nested notifications before
closing any SQLite connection. A drain that exceeds its diagnostic deadline
continues waiting; it does not close stores underneath accepted work.
`SendSIGKILL=no` likewise leaves a stuck shutdown available for investigation.

| Setting | Default | Managed deployment |
| --- | --- | --- |
| `MOCHI_ENV_FILE` | `.env` | `/etc/mochi/mochi.env` |
| `MOCHI_STATE_DIR` | current directory | `/mnt/volume-hel1-1/mochi-state` |
| `MOCHI_HTTP_ADDR` | `:4738` | `127.0.0.1:4738` |
| `MOCHI_REQUIRE_EXISTING` | `0` | `1` |
| `MOCHI_AUTO_MIGRATE` | `enabled` | `disabled` |
| `MOCHI_WORKERS` | `enabled` | `enabled` |
| `MOCHI_WORKER_START_DELAY` | `0s` | `60s` |

State contains `shared.db` and the complete `.user_databases` directory.
Required-existing mode refuses missing shared state or a missing/redirected user
database directory. Existing-user lookups use SQLite `mode=rw`; registration
still deliberately creates its new user database. Filenames, including
email-shaped usernames, are preserved and escaped as SQLite URI paths.
The original configuration bytes and CSRF key must be preserved.

Managed startup validates the required existing tables, columns and unique
indexes without automatic migrations. New registration still deliberately
creates and migrates its own new user database. Existing SQL defaults, legacy
tables, rows and identifiers remain untouched; schema upgrades require a
separately reviewed procedure. Unmanaged installations retain automatic
migration. The two site date fields no longer declare `default:0`: GORM treated
that value as today's midnight and repeatedly rebuilt existing tables.
New sites now start with actual zero dates, as the scheduler expects.

`GET /healthz` is separate from public rate limits and authentication. It reads
the shared schema and user-file inventory without issuing cookies or migrating
stores, and returns `status`, `revision`, `workers` and `userDatabases`.
`workers` describes the configured scheduling mode, not Discord availability.
Listener failures exit unsuccessfully before opening or migrating databases.

`MOCHI_WORKERS=disabled` is an explicit release-compatible rehearsal setting:
it disables periodic cleanup, metrics reports, scheduled outgoing webmentions
and the Discord gateway, but not accepted HTTP analytics or webmention tasks.
Health and startup logs disclose the mode. Copied acceptance environments must
also deny external traffic: HTTP webmention handling can still send a
notification, and authenticated users can request outgoing webmentions.
Never use actual owner credentials or send provider test messages.

The optional initial scheduler delay accepts durations from `0s` to `1h`.
It affects only the first scheduled cleanup, webmention and metrics checks;
normal intervals remain two weeks, seven days and one hour respectively.
The unmanaged default preserves immediate startup checks. The managed unit
waits one minute before the first scheduled checks, allowing startup state
verification without running copied or premature production housekeeping.
The gateway and accepted HTTP work are not delayed. Cancellation stops subsequent
scheduled items after the current item completes; provider REST requests have
a 30-second timeout.

## Deployment and updates

From a clean, committed checkout on Linux amd64 with Python 3.11+ and the
reviewed Go 1.25.6 toolchain:

```sh
python3 scripts/deploy_vps.py meadow-ubuntu-8gb-hel1-1 --yes
```

The updater validates both race-enabled Go modes and deployment regressions,
builds the committed archive, and uploads an immutable binary/assets/templates
release. A serialized transient systemd installer survives SSH disconnects.
The generated stylesheet is tracked in Git so clean source archives include it;
deployment does not regenerate it or upgrade Tailwind. The initial tracked bundle
is the preserved production Tailwind 4.1.18 artifact (SHA-256
`606bd6e66903abe4e15073ba2bccbd601a419c216ee1a690b9f203fd1e898601`).
When deliberately rebuilding CSS, review the Tailwind version and bundle changes,
update the stylesheet URL's `v` value in `templates/layouts/standard.html` to the
first 12 SHA-256 characters, and commit both files. This prevents cached missing
or stale styles from surviving an asset change.
Missing/empty CSS or Chart.js and a mismatched stylesheet cache version block
packaging and installation. Copied startup, live startup, public verification
and no-op checks fetch both assets and verify MIME types and exact release bytes.
The private receipt printed before installation contains logs, configuration
backups, complete SQLite snapshots and `deployment.json`; inspect that receipt
rather than repeating an interrupted command.

Initial migration additionally requires `--migrate-tmux`, `--legacy-pid`,
`--wrapper-pid` and `--legacy-sha256`, obtained from a fresh inspection.
Add `--rehearse` to run copied startup with workers disabled and external traffic
denied, without stopping the legacy processes or changing live routing/state.
Rehearsal prepares the service account and immutable release.

The installer takes the existing Backuper job lock before its application lock.
It verifies complete schema/all-table state, including legacy tables and exact
user database filenames, and requires copied startup to preserve it. A healthy
identical release is a PID-preserving no-op. Actual cutover temporarily replaces
only the two Mochi Caddy proxies with maintenance responses, verifies routing
restoration, and moves the three backup sources and two SQLite-parent write
permissions together under the lock.

Initial migration also drains legacy HTTP and inspects goroutine function names
using pinned Delve 1.25.2 through a root-private Unix socket. Inspection explicitly
detaches without killing the target; accepted/scheduled work blocks migration.
Only identity-checked wrapper/application PIDs are signalled, never the tmux shell.
The original installation is retained.

Releases live under `/opt/mochi/releases`, selected by `/opt/mochi/current`.
The enabled unit runs as the dedicated non-login `mochi` user with mounted-volume
dependencies and read-only release/configuration access. Do not start it against
empty state or stop the legacy wrapper blindly.

`/opt/mochi/deployment-pending.json` blocks subsequent operations after uncertain
shutdown, accepted writes, schema changes or operator configuration edits.
Automatic recovery switches binaries/configuration only when complete state is
unchanged; it never copies an old database over accepted writes. Initial recovery
can launch the untouched original binary in a transient rollback unit, not revive
the git-pull/build wrapper. Resolve the receipt and pending marker deliberately,
preserving current state. Verify an actual restart, public health and both full
encrypted backup restores before considering a migration complete.
