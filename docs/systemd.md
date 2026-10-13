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

From a clean, committed checkout on Linux amd64 with Python 3.11+, Go 1.25.6,
Node 22.22.2 and npm 10.9.7:

```sh
python3 scripts/deploy_vps.py meadow-ubuntu-8gb-hel1-1 --yes
```

The updater extracts the committed archive, runs `npm ci`, generates the CSS
and layout, and validates the CSS build and both race-enabled Go modes before
uploading an immutable binary/assets/templates release. A serialized transient
systemd installer survives SSH disconnects. Node/npm are build-machine tools;
the VPS runtime needs neither.

Tailwind and its compiler are pinned to production's existing 4.1.18 version;
the full dependency graph is locked by `package-lock.json`. `.node-version`,
package engines and `.npmrc` enforce the reviewed Node/npm versions. Builds
invoke the installed CLI directly, never downloading an unpinned CLI with npx.
The generated stylesheet reproduces the original production artifact (SHA-256
`606bd6e66903abe4e15073ba2bccbd601a419c216ee1a690b9f203fd1e898601`)
for the initial source recipe; legitimate source edits generate a new hash.

```sh
npm ci --no-audit --no-fund
npm run build:css
npm run test:css
```

Edit `main.css`, the templates, or `templates/layouts/standard.source.html`,
not generated files. The compiler explicitly scans templates, site code and
asset JavaScript; unrelated checkout files, tests outside those directories,
and the generated layout cannot accidentally add utilities. Tailwind4 sources
are configured in `main.css`, not a legacy JavaScript configuration file.
`assets/css/bundled_styles.css` and `templates/layouts/standard.html` are ignored
build outputs. The layout's stylesheet URL automatically receives the first12
SHA-256 characters. The source layout remains unchanged and is excluded from
the release payload; no manual hash edit or generated-file commit is needed.
Compilation, dependency/version or source-marker failures stop packaging.

For local development, `task run`/`task dev` generate the initial assets; run
`npm run watch:css` alongside the server to rebuild both outputs on source
changes. The existing Tailwind install/watch Taskfile targets use these same
locked commands. `npm run test:e2e` also builds CSS before starting its isolated
server. The legacy unmanaged wrapper builds locked assets before launching;
the managed VPS service never installs packages or compiles CSS at startup.

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
