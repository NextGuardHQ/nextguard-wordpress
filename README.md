# NextGuard Security Scanner — WordPress

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
![WordPress](https://img.shields.io/badge/WordPress-5.6%2B-21759b)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4)
![Version](https://img.shields.io/badge/version-1.1.0-success)

Official WordPress plugin for [NextGuard](https://nextguardhq.com). It syncs your
installed plugins and active theme to your NextGuard project so you can monitor
your WordPress stack for known CVEs from a single dashboard.

## Features

- Daily automatic sync via WP-Cron
- Manual **Sync Now** action in **Settings → NextGuard**
- Syncs every installed plugin (slug + version) and the active theme
- Device authorization flow — activate without copy-pasting keys
- Requests signed with HMAC-SHA256; the API key is never exposed to the browser

## Requirements

- WordPress 5.6 or newer
- PHP 7.4 or newer
- A NextGuard account on the **Starter** plan or above (CMS plugin sync is included from Starter)

## Installation

### Method 1 — WordPress admin upload (recommended)

1. Download the latest `nextguard.zip` from the [Releases](../../releases) page.
2. In WordPress Admin go to **Plugins → Add New → Upload Plugin**.
3. Upload the zip, then click **Activate**.
4. Go to **Settings → NextGuard** and follow the on-screen activation, or paste your
   **API Key** and **Project ID** from your NextGuard dashboard.
5. Click **Save Settings**, then **Sync Now** to verify the connection.

### Method 2 — Manual upload (FTP / cPanel)

1. Download and unzip the release.
2. Upload the `nextguard/` folder into `wp-content/plugins/`.
3. Activate **NextGuard** under **Plugins → Installed Plugins** and configure as above.

## Configuration

| Setting    | Where to find it                                |
|------------|-------------------------------------------------|
| API Key    | NextGuard → **Account → API Keys**              |
| Project ID | NextGuard → your project → **Settings** (UUID)  |

## How it works

On activation the plugin schedules a daily WP-Cron job. Each run:

1. Collects installed plugins via `get_plugins()`.
2. Collects the active theme via `wp_get_theme()`.
3. Sends a signed `POST` to `https://nextguardhq.com/api/v1/cms/sync` with your
   API key in the `X-API-Key` header.

The request is non-blocking, so syncing never affects page-load time.

### Payload

```json
{
  "projectId": "your-project-uuid",
  "cmsType": "wordpress",
  "components": [
    { "slug": "woocommerce/woocommerce.php", "version": "8.3.1", "name": "WooCommerce", "type": "plugin" },
    { "slug": "storefront", "version": "4.5.0", "name": "Storefront", "type": "theme" }
  ]
}
```

## Troubleshooting

**Sync does not run automatically** — WP-Cron only fires on HTTP traffic. On
low-traffic sites, trigger it with a real cron job:

```cron
*/15 * * * * curl -s "https://yoursite.com/wp-cron.php?doing_wp_cron" >/dev/null 2>&1
```

**Invalid API Key** — Re-check **Settings → NextGuard**; the key must match the one
shown in your NextGuard dashboard exactly.

**Project not found** — The Project ID must be the full UUID from your project's
**Settings** page.

## License

Released under the [GNU General Public License v2.0](LICENSE) or later, consistent
with the WordPress plugin ecosystem.
