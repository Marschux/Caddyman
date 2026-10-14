# Changelog

## 2026-10-14 02:17
- chore: version 0.17.5
- feat: the descriptions on every page are shorter


## 2026-10-14 02:10
- chore: version 0.17.4
- feat: the hints in the route form are much shorter, a target copied from the browser is taken, and further hostnames are folded in the route list


## 2026-10-14 01:59
- chore: version 0.17.0
- fix: the lock on a second factor grows, the own password and the last account that manages users are guarded, groups and error pages no longer overwrite a change made meanwhile, and smaller hardening from the audit
- fix: wrong passwords count against the account name as well as the address, and downloading a backup takes the right for routes too
- fix: setting up two-factor login takes the password, a mailed link ends with a corrected address, the admin login is kept only for the same address and sent checked against the remembered CA, a route keeps its single sign-on when the snippet is missing
- fix: the route for unknown names is no longer in the route list, it is switched on and off under Error pages
- docs: an example for the base Caddyfile


## 2026-10-13 22:38
- chore: version 0.16.1
- docs: the README is shorter: one line per feature, six variables, six things to know, and no word on user management being left out
- docs: the README drops the section on users
- docs: the README drops the Logs screenshot, the note on optional blocks and the section on the admin API
- docs: the installation is five short steps, the optional blocks are left to the pages that show them


## 2026-10-13 22:24
- chore: version 0.16.0
- feat: logging out ends every session of the account, the email address changes only with the password, an import takes the right for routes, and what Caddy said to a rejected reload is shown only to who may change routes
- fix: a request larger than any form, or one that does not say its length, is refused before it is read
- fix: the status page keeps its checks for ten seconds instead of asking again on every reload
- fix: route files and the data files are put in place in one step, never cut short by a crash
- fix: with the open trust page switched off, it takes the right for the Root CA page
- fix: an error page only answers for the errors Caddy hands over
- fix: whether a route file exists already is looked at under the write lock
- fix: the table of failed logins drops entries that are neither locked nor recent
- fix: a second-factor code is checked and used up under one lock
- fix: the message for the next page is signed with a key of its own and marked Secure over HTTPS
- fix: an archive that does not unpack is refused as unreadable, and host values from an archive are trimmed
- fix: a route file whose metadata has a number where text belongs is treated as hand-written
- fix: an allowed network with an IPv6 zone is refused
- fix: a name, target or path with a line break at its end is refused


## 2026-10-13 21:11
- chore: version 0.15.7
- fix: changing the mail settings takes the right to manage users as well, and the paths of Caddy's files cannot point into Caddyman's own data
- fix: forms from another site are refused, the login limit survives another login and counts codes per account, mailed tokens are hidden on the Logs page, the admin login only goes to a server that shows the remembered CA
- fix: login and rights go by the path the router uses, not by one rebuilt from the Host header
- chore: version 0.15.6
- refactor: the tests share one helper each for patching, a second browser and writing a route file
- refactor: one host instead of a list, one place each for encrypting, the check code and the admin API check
- refactor: the list of time zones is collected once, the keys of a second factor are named once
- refactor: the status checks leave out the empty last argument
- refactor: one helper each for the data files, the admin API, a target and a missing Caddy


## 2026-10-13 18:47
- docs: tidy the changelog


## 2026-10-13 18:44
- chore: version 0.15.5
- feat: a changed address for the error pages is part of the backup


## 2026-10-13 18:29
- chore: version 0.14.3
- feat: the time zone chosen under Settings is part of the backup
- feat: General and Security are one block in the settings, Mail is called SMTP
- chore: the time zone is set in the .env, the reset variable reads true or false
- feat: time zone under Settings, an HTTPS-only switch, an x to remove a hostname, network or path, the group always in sight, import in address and change log
- feat: the route form folds its options into blocks, allowed networks get a field each, restore is called import
- feat: avatars in the user list and the profile wear the product colour, like the one in the header
- feat: time zone for the times in the logs, and the change log as a page of its own under System
- feat: four more designs for the error pages: unicorn, space, gaming and forest
- feat: the designs of the error pages are part of the backup
- fix: the address for a DNS blocker also shows when Caddyman is opened under a name
- feat: the address for a DNS blocker can be copied from the error pages
- fix: error pages say what the address is for and show that the catch-all is on
- feat: error pages in a design per error, for routes and as a catch-all for a DNS blocker


## 2026-10-13 02:09
- chore: version 0.13.3
- feat: wildcard names for routes, with the DNS challenge or Caddy's internal CA
- docs: new screenshot of the route list
- feat: the route list checks the target of every path as well
- feat: the Caddy settings show image, variables and snippet for the DNS challenge per provider
- feat: Let's Encrypt over the DNS challenge as a TLS mode, through a snippet in the base Caddyfile
- feat: the status page says when a snippet stands below the import of the routes
- feat: a route can send the HSTS header
- feat: a route can be put behind a single sign-on through a forward_auth snippet
- feat: paths of a route can go to targets of their own
- fix: an added hostname field shows a hint instead of an example that reads like a value
- feat: further hostnames get a field each, added by a button and laid out in two columns
- feat: a route can answer to more hostnames besides its main one
- fix: a switched-off route no longer shows two shades under the pointer
- feat: a route can be limited to addresses and networks, everybody else gets a 403
- feat: a route can be switched off and on again from the route list, its file is kept
- feat: a route can skip the certificate check of an https target with a self-signed certificate
- feat: sub-page titles stand above the content, rights are written out, the theme button stays at the right in a narrow window
- fix: a table beside the side list scrolls below 1100px instead of running off the page
- chore: ignore docs, screenshots live under assets


## 2026-10-12 23:58
- moved folder


## 2026-10-12 15:41
- chore: version 0.12.0
- feat: footer names the author
- fix: a target only Caddy can reach (container name, loopback) is no longer a link in the route list
- feat: white buttons and the file button get the product colour as border under the pointer too
- feat: grey and outlined buttons get the product colour as border under the pointer
- feat: copy buttons wear the product colour
- feat: No groups is a toggle button in the last column title of the route list
- feat: the route list remembers No groups in the browser
- feat: No groups in the route list shows one list without the group names, instead of only routes without a group
- feat: route form has Edit as text as a button next to the title; route list can show only routes without a group
- fix: a button in a wide card is as wide as its text; unused red delete rule removed
- feat: top right is one group: the account as a pill with turquoise initials, log out as an icon button
- fix: users list keeps its shape: address under the name, one label for all rights, even distances between the buttons
- feat: root CA page has steps for Chrome and Edge, and for Firefox on Android
- feat: settings forms are as wide as the other pages with a side list
- feat: route list has a column for the options of a route, with short labels
- feat: a good certificate in the route list only says how long it lasts, the issuer is in the tooltip
- chore: screenshots in docs/assets, pre-push hook in .github/hooks


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
