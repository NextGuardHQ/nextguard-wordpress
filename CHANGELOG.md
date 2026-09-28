# Changelog

All notable changes to the NextGuard WordPress plugin are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0]

### Added
- Deployment integrity: every plugin reports its installation `path` and, for
  plugins published on WordPress.org, the result of comparing its files with the
  official checksums (`verified` / `modified` with the list of changed files /
  `unverifiable` for premium or custom plugins). Results are cached for 24 hours
  and each sync has a time and plugin budget, so large sites never time out.
- All installed themes are sent (not only the active one), each with its state.
- Optional environment token (`vs_pe_…`) in a new "Environment" settings form, to
  bind this site's inventory to the right NextGuard environment even when its URL
  differs. Stored in its own settings group so saving it never clears the API key.
- `collector` block (`version`, `complete`) in the sync payload.

### Notes
- Inactive plugins were already sent with `active: false`; NextGuard now keeps
  them as deployed components (an inactive plugin's files are still reachable).
- Backwards compatible: every new field is optional for the server.

## [1.3.0]

### Added
- Internal security audit is now sent alongside the plugin/theme inventory on each
  sync (previously the sync carried inventory only). Checks cover configuration
  (`WP_DEBUG`, file-editor / RCE surface, open registration, XML-RPC, admin HTTPS),
  outdated core/plugins/themes, risky users (default `admin` login, author
  enumeration) and `wp-config.php` permissions.

### Security
- Findings never carry raw usernames or file contents — account names are masked.

### Notes
- Additive and fail-safe: if the audit errors, the inventory sync still succeeds.

## [1.2.0]

### Added
- Anonymous free scan: paste a `vs_pk_anon_` key to scan with no account; results
  (vulnerability table + severity counts) render right in the plugin admin.
- "Create an account" panel: live Free / Monitoring / Starter plans loaded from
  the dashboard (`/api/public/plans`), with a static fallback. Single source of
  truth shared with the website pricing.
- Last-scan date stored and shown above the results.
- Full i18n: 9 languages (.po/.mo), generated with WordPress' own PO/MO classes.
- `uninstall.php`: removes every `nextguard_*` option, transient and cron event.

### Changed
- Free anonymous key is limited to 3 scans within its 2-hour TTL.
- API base always defaults to production; override only via `NEXTGUARD_API_BASE`
  in `wp-config.php`.

## [1.1.0]

### Added
- Device authorization flow (`ng_dev_*` tokens) for keyless activation.
- Daily automatic sync via WP-Cron with manual "Sync Now" action.

### Changed
- Sync requests are now signed with HMAC-SHA256 (`X-NG-Signature`).

## [1.0.0]

### Added
- Initial release: syncs installed plugins and the active theme to NextGuard
  for continuous CVE monitoring.
