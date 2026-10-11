# Changelog

## 2026-10-11 23:52
- chore: version 0.10.0
- feat: disconnect and send a test mail are buttons above their settings block
- feat: root CA download button sits one row below the title
- feat: reload Caddy on the status page is a button
- feat: add group and add route sit in the row of the search
- feat: route list with search, only problems and sorting by column, delete in lists wears the product colour
- feat: groups for routes, created next to add route and picked in the route form, the list shows its routes by group
- feat: copy button in every box with a command or a value, the long Windows command shows only its start
- feat: root CA page lists the systems at the left edge and shows one at a time
- feat: users page without the note about forgotten passwords
- fix: https admin API with a certificate from a private CA is accepted, its CA is remembered on save
- feat: root CA switches moved into the security block
- feat: system tab for status, logs and backup, with the same list at the left edge
- feat: settings blocks as a list at the left edge
- feat: settings tab with Caddy, root CA, mail, users and security, two-factor login can be required
- feat: mail is set up in the interface instead of through variables
- feat: users with rights per area, two-factor login, password reset by mail and a profile page
- feat: route list stays one line for a certificate problem, explanation as tooltip
- feat: root CA instructions for macOS, iPhone, iPad and Android


## 2026-10-11 18:46
- chore: version 0.9.0
- feat: no name for the one Caddy, clearer labels for the two layouts
- feat: status page offers a route for Caddyman itself while it is reached without HTTPS
- feat: CADDYMAN_SETUP_TOKEN needs at least 12 characters
- feat: larger brand on the login page, same size as on the setup page
- fix: brand on the setup page one and a half times the size
- feat: setup page without the bar, brand twice the size above the form
- feat: admin account only through the setup page, CADDYMAN_ADMIN_USER and CADDYMAN_ADMIN_PASSWORD_HASH removed
- feat: setup token can be set with CADDYMAN_SETUP_TOKEN
- feat: two switches for the root CA, open page and hint on the login page


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
