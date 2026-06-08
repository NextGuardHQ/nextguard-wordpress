# Changelog

All notable changes to the NextGuard WordPress plugin are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project adheres to [Semantic Versioning](https://semver.org/).

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
