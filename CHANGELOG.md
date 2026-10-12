# Changelog

## 2026-10-12 02:12
- chore: version 0.11.0
- feat: status page asks for the two words an older log setup lacks, where they matter
- feat: the Caddy from the settings is trusted by itself for HTTPS and the visitor's address, no variable needed
- fix: root CA page follows the switch for the open page again; docs: new screenshots, the two root CA switches
- feat: status page says when HTTPS in front of Caddyman goes unnoticed, and keeps pointing at the own route while the page comes in unencrypted
- fix: the conflict box keeps its distance from the form below it
- feat: logs page reads older parts and the rotated files of a Caddy elsewhere, a route can write its own access log
- refactor: one Caddy, so no host parameter in addresses and handlers any more
- feat: the switch between the dark and the light look is a button in the bar, next to the account
- feat: light look per account, CA of the admin API can be pasted, layouts are called shared files and network only, live log over the network every 20 seconds
- feat: route list keeps certificate and target checks for a while and never waits long for one that hangs, rotated logs are listed, file button in the dark look
- feat: adopt takes basic auth and host header, hand-written routes show their certificate, disconnect removes the copies kept for a Caddy elsewhere
- feat: status page says when the secret key was made by Caddyman instead of coming from the environment
- feat: the route to Caddyman itself keeps only the warning before deleting, the tag and the form hint are gone
- feat: the route that leads to Caddyman itself is marked, with a word of warning before deleting or changing it
- docs: what the secret key protects and what to do after changing it
- feat: the mail port follows the encryption unless it was set by hand
- fix: restoring into an install without a Caddy needs the right to change the settings
- fix: a restore that Caddy rejects leaves groups, switches, mail settings and the connection to Caddy untouched
- feat: setup page takes an optional email address for the admin account
- feat: add user says why a password is needed while mail is not set up
- feat: user list marks invited accounts and can send the invitation again
- feat: backup holds groups, the security switches, the mail settings without the password and the remembered CA of the admin API
- feat: a new account can be invited by mail and sets its own password, the link works once for one day
- feat: mail settings take a CA certificate for a mail server with a certificate from a private CA
- fix: the mark of the open tab and list entry is a clean aria-current attribute
- feat: a root CA source with several certificates gives each its own download, check code and command
- feat: status page checks that the ACME CA answers and that the root CA can be downloaded
- feat: version number in the footer links to the source, the separate link is gone


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
