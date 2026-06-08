<?php
/**
 * Runs when the user DELETES the NextGuard plugin from WordPress.
 * Removes every option / transient / scheduled event the plugin created so no
 * data is left behind. (Deactivation only unschedules the cron — it keeps the
 * settings in case the user reactivates.)
 */

// Guard — only WordPress' uninstall routine may run this file.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

$nextguard_options = [
    'nextguard_api_key',
    'nextguard_token',
    'nextguard_project_id',
    'nextguard_project_name',
    'nextguard_last_sync',
    'nextguard_last_preview',
    'nextguard_register_url',
    'nextguard_syncs_remaining',
    'nextguard_max_syncs',
    'nextguard_last_scan',
    'nextguard_plan_links',
];

$nextguard_cleanup = function () use ($nextguard_options) {
    foreach ($nextguard_options as $opt) {
        delete_option($opt);
    }
    delete_transient('nextguard_activation_code');
    $ts = wp_next_scheduled('nextguard_sync_cron');
    if ($ts) {
        wp_unschedule_event($ts, 'nextguard_sync_cron');
    }
};

$nextguard_cleanup();

// Multisite: clean each site's options too.
if (is_multisite()) {
    global $wpdb;
    $blog_ids = $wpdb->get_col("SELECT blog_id FROM {$wpdb->blogs}");
    foreach ($blog_ids as $blog_id) {
        switch_to_blog($blog_id);
        $nextguard_cleanup();
        restore_current_blog();
    }
}
