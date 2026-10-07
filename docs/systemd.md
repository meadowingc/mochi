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
| `MOCHI_WORKERS` | `enabled` | `enabled` |
| `MOCHI_WORKER_START_DELAY` | `0s` | `0s` |

State contains `shared.db` and the complete `.user_databases` directory.
Required-existing mode refuses missing shared state or a missing/redirected user
database directory. Existing-user lookups use SQLite `mode=rw`; registration
still deliberately creates its new user database. Filenames, including
email-shaped usernames, are preserved and escaped as SQLite URI paths.
The original configuration bytes and CSRF key must be preserved.

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
The default preserves immediate startup checks. Cancellation stops subsequent
scheduled items after the current item completes; provider REST requests have
a 30-second timeout.

The unit is a deployment template, not a completed installer. Do not start it
against empty state, stop the legacy wrapper blindly, or restore an old database
over newly accepted writes. The rollout still requires a guarded updater,
complete copied-state rehearsal, isolated authenticated acceptance, scoped
legacy drain and verified backup retargeting.
