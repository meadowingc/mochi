# Security and incident response

Report security concerns privately to the Mochi operator. Do not include passwords,
session cookies, API keys, database files, or unredacted user data in public issues.

## Incident handling

1. Preserve the original report and relevant logs before changing the system.
   Record SHA-256 checksums, restrict access, and use redacted copies for
   collaboration.
2. Record the host timezone and convert timestamps to UTC before correlating
   application, proxy, mail, and host evidence.
3. Gracefully stop Mochi before copying `shared.db` and `.user_databases` so
   SQLite can checkpoint its WAL files. Verify backups read-only before rollout.
4. Record the deployed commit and binary checksum, process owner, listeners,
   reverse-proxy configuration, database permissions, and relevant file
   modification times.
5. Preserve pre-incident proxy/CDN, mail, authentication, host, and egress logs.
   A clean log window after an incident does not rule out an earlier compromise.

Keep routine application logs free of usernames, raw route identifiers, cookies,
keys, and complete attacker-supplied URLs. Security logs at the reverse proxy
should have restricted access and a documented, short retention period.

## Investigation checklist

Review:

- legacy analytics and webmention paths containing email-shaped usernames;
- `POST` requests to webmention receivers, which trigger outbound validation;
- bursts of login, registration, and password-reset submissions;
- analytics API probes across usernames, public IDs, or site IDs;
- `.env`, `.git`, cloud credential, CMS, and file-manager probes that returned
  anything other than the expected `404`;
- unexpected access or changes to `.env`, `shared.db`, and `.user_databases`;
- process starts, shell access, privilege changes, and outbound requests to
  private, link-local, or cloud-metadata addresses.

Do not visit URLs or execute attachments supplied in an incident report.

## Containment and rotation

Invalidate Mochi sessions when session data may have been exposed. Rotate site
analytics API keys when database access is suspected. Rotate CSRF, Discord, and
deployment secrets when `.env`, process memory, or host access may have been
compromised. Preserve old evidence before rotating or deleting anything.

## Public route migration

Canonical integrations use opaque per-site public IDs. Legacy username-based
analytics, webmention, and API routes remain compatible, but an old snippet can
continue publishing its username in the embedding site's HTML. Users with
email-shaped usernames should replace every legacy analytics and webmention
snippet even though the old URL still works.

Opaque public IDs identify a site; they are not authorization credentials.
Private analytics API access still requires the site's API key.

## Security testing

Run the isolated Chromium end-to-end suite with:

```sh
npm run test:e2e:install
npm run test:e2e
```

The launcher builds a debug binary in a fresh OS temporary directory and keeps
its `.env` and databases separate from repository development data.
