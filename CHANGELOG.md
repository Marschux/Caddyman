# Changelog

## 2026-10-09 17:37
- feat: login page without the bar, brand centred above the form, version 0.8.14
- feat: root CA hint as its own card on the login page, version 0.8.13
- feat: root certificate without a login, check code and a self-checking install command, version 0.8.12
- fix: Windows import command points at the download folder, version 0.8.11
- feat: target icons removed from the route list again, version 0.8.10
- feat: target icons, outlined buttons and a single-line route list, version 0.8.9
- feat: route list with links, counter and type under the hostname, version 0.8.8
- feat: test target button removed from the route list, version 0.8.7
- feat: target without a port, version 0.8.6
- feat: unreachable targets marked in the route list, version 0.8.5


## 2026-10-09 01:47
- feat: admin API behind a login by default, version 0.8.4


## 2026-10-09 01:39
- feat: license and source link in the footer, version 0.8.3


## 2026-10-09 01:35
- docs: shorter README with numbered installation steps


## 2026-10-09 01:32
- feat: favicon, version 0.8.2
- feat: logs without setup, live and for a Caddy elsewhere, version 0.8.1
- feat: log viewer, version 0.8.0
- feat: one Caddy per Caddyman, version 0.7.2
- chore: version 0.7.1
- feat: black, flat look
- feat: new look in Caddy's colours, version 0.7.0


## 2026-10-09 00:52
- fix: changelog hook only runs when the current branch is pushed


## 0.6.0 - 2026-10-09

First release.

- Routes for reverse proxy, redirect and static files, one file per route in Caddy's sites directory
- Four TLS modes per route: own ACME CA, Caddy default, Caddy's internal CA, none
- Every change is written and loaded into Caddy in one step; if Caddy rejects it, the file is put back as it was
- Basic auth and the upstream Host header as options for reverse proxy routes
- Routes created here open in a form, all others as text; hand-written routes that match a known pattern can be adopted
- A route changed on disk while it was being edited is shown next to the pending version instead of being overwritten
- Certificate column: issuer and remaining lifetime of what each route really serves, with a warning when a route meant for the own CA got its certificate from Caddy's internal one
- Root CA page with download, fingerprints and import instructions for Windows, Debian and Firefox
- Backup and restore of all routes as a ZIP, with a preview before anything is written
- Caddy on the same machine (shared files) or on another machine (routes kept by Caddyman and pushed as one Caddyfile), with an optional login for the admin API
- Status page with read-only checks of the base Caddyfile, the admin API and the sites directory, and a log of recent changes
- First start is protected by a setup token printed to the log; login is rate limited per address
