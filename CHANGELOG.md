# Changelog

All notable changes to the NextGuard WordPress plugin are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/) and the
project adheres to [Semantic Versioning](https://semver.org/).

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
