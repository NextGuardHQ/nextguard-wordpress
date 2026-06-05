<?php
/**
 * Plugin Name: NextGuard Security Scanner
 * Plugin URI:  https://nextguardhq.com
 * Description: Syncs your installed plugins and themes to NextGuard for continuous CVE monitoring.
 * Version:     1.1.0
 * Author:      NextGuard
 * Author URI:  https://nextguardhq.com
 * License:     GPLv2 or later
 * Text Domain: nextguard
 */

defined('ABSPATH') || exit;

define('NEXTGUARD_VERSION',          '1.1.0');
define('NEXTGUARD_ACTIVATE_URL',     'https://nextguardhq.com/api/v1/auth/activate');
define('NEXTGUARD_STATUS_URL',       'https://nextguardhq.com/api/v1/auth/activate');
define('NEXTGUARD_API_URL',          'https://nextguardhq.com/api/v1/cms/sync');
define('NEXTGUARD_OPTION_API_KEY',   'nextguard_api_key');
define('NEXTGUARD_OPTION_TOKEN',     'nextguard_token');       // device token (ng_dev_...)
define('NEXTGUARD_OPTION_PROJECT_ID','nextguard_project_id');  // auto-filled after auth
define('NEXTGUARD_CRON_HOOK',        'nextguard_sync_cron');

// ── Activation / deactivation ────────────────────────────────────────────────

register_activation_hook(__FILE__, 'nextguard_activate');
register_deactivation_hook(__FILE__, 'nextguard_deactivate');

function nextguard_activate() {
    if (!wp_next_scheduled(NEXTGUARD_CRON_HOOK)) {
        wp_schedule_event(time(), 'daily', NEXTGUARD_CRON_HOOK);
    }
    nextguard_sync();
}

function nextguard_deactivate() {
    $timestamp = wp_next_scheduled(NEXTGUARD_CRON_HOOK);
    if ($timestamp) wp_unschedule_event($timestamp, NEXTGUARD_CRON_HOOK);
}

// ── Cron sync ────────────────────────────────────────────────────────────────

add_action(NEXTGUARD_CRON_HOOK, 'nextguard_sync');
add_action('upgrader_process_complete', 'nextguard_sync');   // after plugin updates
add_action('activated_plugin',          'nextguard_sync');
add_action('deactivated_plugin',        'nextguard_sync');

/**
 * Returns the effective signing/auth key: device token if present, else legacy api_key.
 */
function nextguard_effective_key(): string {
    $token = get_option(NEXTGUARD_OPTION_TOKEN, '');
    if (!empty($token)) return $token;
    return get_option(NEXTGUARD_OPTION_API_KEY, '');
}

function nextguard_sync() {
    $auth_key   = nextguard_effective_key();
    $project_id = get_option(NEXTGUARD_OPTION_PROJECT_ID, '');

    if (empty($auth_key) || empty($project_id)) return;

    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins  = get_plugins();
    $active_slugs = (array) get_option('active_plugins', []);
    $components   = [];

    foreach ($all_plugins as $path => $data) {
        $components[] = [
            'name'    => sanitize_text_field($data['Name']),
            'slug'    => dirname($path) ?: basename($path, '.php'),
            'version' => sanitize_text_field($data['Version']),
            'type'    => 'plugin',
            'active'  => in_array($path, $active_slugs, true),
        ];
    }

    // Active theme
    $theme = wp_get_theme();
    $components[] = [
        'name'    => $theme->get('Name'),
        'slug'    => $theme->get_stylesheet(),
        'version' => $theme->get('Version'),
        'type'    => 'theme',
        'active'  => true,
    ];

    // Parent theme if child theme active
    if ($theme->parent()) {
        $parent = $theme->parent();
        $components[] = [
            'name'    => $parent->get('Name'),
            'slug'    => $parent->get_stylesheet(),
            'version' => $parent->get('Version'),
            'type'    => 'theme',
            'active'  => true,
        ];
    }

    $body = wp_json_encode([
        'projectId'  => $project_id,
        'cmsType'    => 'wordpress',
        'cmsVersion' => get_bloginfo('version'),
        'phpVersion' => PHP_VERSION,
        'siteUrl'    => home_url(),
        'components' => $components,
    ]);

    // HMAC-SHA256 request signing — sign with device token (or legacy api_key)
    $timestamp   = time();
    $url_path    = '/api/v1/cms/sync';
    $body_hash   = hash('sha256', $body);
    $sig_payload = "{$timestamp}\nPOST\n{$url_path}\n{$body_hash}";
    $signature   = 'sha256=' . hash_hmac('sha256', $sig_payload, $auth_key);

    $response = wp_remote_post(NEXTGUARD_API_URL, [
        'headers'  => [
            'Content-Type'    => 'application/json',
            'X-API-Key'       => $auth_key,
            'X-NG-Timestamp'  => (string) $timestamp,
            'X-NG-Signature'  => $signature,
        ],
        'body'     => $body,
        'timeout'  => 15,
        'blocking' => false,   // fire-and-forget
    ]);

    if (!is_wp_error($response)) {
        update_option('nextguard_last_sync', current_time('mysql'));
    }
}

// ── AJAX: Request activation code ────────────────────────────────────────────

add_action('wp_ajax_nextguard_request_code', 'nextguard_ajax_request_code');

function nextguard_ajax_request_code() {
    if (!current_user_can('manage_options')) wp_die('Unauthorized', 403);
    check_ajax_referer('nextguard_ajax', 'nonce');

    $api_key = sanitize_text_field($_POST['api_key'] ?? '');
    if (empty($api_key)) {
        wp_send_json_error(['message' => __('API key is required.', 'nextguard')]);
    }
    if (strpos($api_key, 'vs_pk_') !== 0) {
        wp_send_json_error(['message' => __('Invalid API key. Keys must start with vs_pk_', 'nextguard')]);
    }

    // Persist the API key so we can sign future requests
    update_option(NEXTGUARD_OPTION_API_KEY, $api_key);

    $response = wp_remote_post(NEXTGUARD_ACTIVATE_URL, [
        'headers' => [
            'Content-Type' => 'application/json',
            'X-API-Key'    => $api_key,
        ],
        'body'    => '{}',
        'timeout' => 15,
    ]);

    if (is_wp_error($response)) {
        wp_send_json_error(['message' => $response->get_error_message()]);
    }

    $body = json_decode(wp_remote_retrieve_body($response), true);
    $code = $body['code'] ?? '';
    if (empty($code)) {
        wp_send_json_error(['message' => __('Failed to get activation code from NextGuard. Check your API key.', 'nextguard')]);
    }

    // Store code + expiry in a transient (15 min)
    set_transient('nextguard_activation_code', $code, $body['expiresIn'] ?? 900);

    wp_send_json_success(['code' => $code, 'expiresIn' => $body['expiresIn'] ?? 900]);
}

// ── AJAX: Poll activation status ──────────────────────────────────────────────

add_action('wp_ajax_nextguard_poll_status', 'nextguard_ajax_poll_status');

function nextguard_ajax_poll_status() {
    if (!current_user_can('manage_options')) wp_die('Unauthorized', 403);
    check_ajax_referer('nextguard_ajax', 'nonce');

    $code = get_transient('nextguard_activation_code');
    if (empty($code)) {
        wp_send_json_error(['message' => __('No pending activation. Please request a new code.', 'nextguard'), 'status' => 'expired']);
    }

    $response = wp_remote_get(NEXTGUARD_STATUS_URL . '?code=' . urlencode($code), [
        'timeout' => 10,
    ]);

    if (is_wp_error($response)) {
        wp_send_json_error(['message' => $response->get_error_message()]);
    }

    $body   = json_decode(wp_remote_retrieve_body($response), true);
    $status = $body['status'] ?? 'unknown';

    if ($status === 'authorized') {
        $token        = sanitize_text_field($body['token'] ?? '');
        $project_id   = sanitize_text_field($body['projectId'] ?? '');
        $project_name = sanitize_text_field($body['projectName'] ?? '');

        update_option(NEXTGUARD_OPTION_TOKEN,      $token);
        update_option(NEXTGUARD_OPTION_PROJECT_ID, $project_id);
        update_option('nextguard_project_name',    $project_name);
        delete_transient('nextguard_activation_code');

        wp_send_json_success([
            'status'      => 'authorized',
            'projectName' => $project_name,
            'projectId'   => $project_id,
        ]);
    }

    wp_send_json_success(['status' => $status]);
}

// ── Admin settings page ───────────────────────────────────────────────────────

add_action('admin_menu', 'nextguard_admin_menu');

function nextguard_admin_menu() {
    add_options_page(
        __('NextGuard Security', 'nextguard'),
        __('NextGuard', 'nextguard'),
        'manage_options',
        'nextguard',
        'nextguard_settings_page'
    );
}

add_action('admin_init', 'nextguard_register_settings');

function nextguard_register_settings() {
    // Only the API key is user-editable; token + project_id are auto-filled via device auth
    register_setting('nextguard_settings', NEXTGUARD_OPTION_API_KEY, [
        'sanitize_callback' => 'sanitize_text_field',
    ]);
}

function nextguard_settings_page() {
    if (!current_user_can('manage_options')) wp_die(__('Unauthorized'));

    // Manual sync trigger
    if (isset($_POST['nextguard_manual_sync']) && check_admin_referer('nextguard_manual_sync')) {
        nextguard_sync();
        add_settings_error('nextguard', 'synced', __('Sync triggered — check your NextGuard dashboard in a few seconds.', 'nextguard'), 'updated');
    }

    settings_errors('nextguard');

    $last_sync    = get_option('nextguard_last_sync', null);
    $token        = get_option(NEXTGUARD_OPTION_TOKEN, '');
    $project_id   = get_option(NEXTGUARD_OPTION_PROJECT_ID, '');
    $project_name = get_option('nextguard_project_name', '');
    $api_key      = get_option(NEXTGUARD_OPTION_API_KEY, '');
    $is_connected = !empty($token) && !empty($project_id);
    $nonce        = wp_create_nonce('nextguard_ajax');

    // Legacy reconnect notice: has api_key + project_id but no device token
    $show_reconnect = (!empty($api_key) && !empty($project_id) && empty($token));
    ?>
    <div class="wrap">
        <h1><span style="color:#ef4444">&#9632;</span> NextGuard Security Scanner</h1>
        <p><?php _e('Automatically syncs your installed plugins and themes to <a href="https://nextguardhq.com" target="_blank">NextGuard</a> for continuous CVE monitoring.', 'nextguard'); ?></p>

        <?php if ($show_reconnect): ?>
        <div class="notice notice-warning">
            <p><?php _e('<strong>NextGuard:</strong> Your site is using a legacy API key configuration. Please reconnect below using the new Device Authorization Flow.', 'nextguard'); ?></p>
        </div>
        <?php endif; ?>

        <?php if ($is_connected): ?>
        <!-- ── Connected state ── -->
        <div id="nextguard-connected" style="background:#f0fdf4;border:1px solid #86efac;padding:16px 20px;border-radius:6px;margin:20px 0;">
            <p style="margin:0 0 8px;font-size:15px;">
                <strong style="color:#16a34a">&#10003; <?php _e('Connected', 'nextguard'); ?></strong>
            </p>
            <p style="margin:0;"><?php printf(__('Project: <strong>%s</strong> <span style="color:#6b7280;font-size:12px">(%s)</span>', 'nextguard'), esc_html($project_name ?: $project_id), esc_html($project_id)); ?></p>
            <p style="margin:8px 0 0;"><a href="#" id="nextguard-reconnect-link" style="color:#6b7280;font-size:12px;"><?php _e('Connect a different project', 'nextguard'); ?></a></p>
        </div>

        <div id="nextguard-connect-form" style="display:none;">
        <?php else: ?>
        <div id="nextguard-connect-form">
        <?php endif; ?>

            <!-- ── Step 1: Enter API key + request code ── -->
            <div id="nextguard-step-1">
                <h2><?php _e('Connect to NextGuard', 'nextguard'); ?></h2>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="nextguard_api_key_input"><?php _e('API Key', 'nextguard'); ?></label></th>
                        <td>
                            <input type="password" id="nextguard_api_key_input"
                                   value="<?php echo esc_attr($api_key); ?>"
                                   class="regular-text" placeholder="vs_pk_..." />
                            <p class="description"><?php _e('Find this in <a href="https://nextguardhq.com/account" target="_blank">Account → API Keys</a>. Requires Starter plan or higher.', 'nextguard'); ?></p>
                        </td>
                    </tr>
                </table>
                <button type="button" id="nextguard-get-code" class="button button-primary"><?php _e('Connect', 'nextguard'); ?></button>
                <span id="nextguard-step1-spinner" style="display:none;margin-left:8px;" class="spinner is-active"></span>
                <p id="nextguard-step1-error" style="color:#dc2626;display:none;"></p>
            </div>

            <!-- ── Step 2: Show code + poll ── -->
            <div id="nextguard-step-2" style="display:none;background:#fffbeb;border:1px solid #fcd34d;padding:16px 20px;border-radius:6px;margin:16px 0;">
                <p style="margin:0 0 8px;"><?php _e('Go to <a href="https://nextguardhq.com/account" target="_blank">nextguardhq.com/account → Connected Devices</a> and enter this code:', 'nextguard'); ?></p>
                <p style="font-size:28px;font-weight:700;letter-spacing:4px;color:#1e293b;margin:12px 0;" id="nextguard-code-display"></p>
                <p style="color:#6b7280;font-size:12px;margin:0 0 12px;" id="nextguard-code-expiry"></p>
                <button type="button" id="nextguard-poll-btn" class="button button-primary"><?php _e("I've authorized it — Continue", 'nextguard'); ?></button>
                <span id="nextguard-step2-spinner" style="display:none;margin-left:8px;" class="spinner is-active"></span>
                <p id="nextguard-step2-error" style="color:#dc2626;display:none;"></p>
            </div>

        </div><!-- #nextguard-connect-form -->

        <hr />
        <h2><?php _e('Manual Sync', 'nextguard'); ?></h2>
        <?php if ($last_sync): ?>
            <p><?php printf(__('Last sync: <strong>%s</strong>', 'nextguard'), esc_html($last_sync)); ?></p>
        <?php endif; ?>
        <form method="post">
            <?php wp_nonce_field('nextguard_manual_sync'); ?>
            <input type="hidden" name="nextguard_manual_sync" value="1" />
            <?php submit_button(__('Sync Now', 'nextguard'), 'secondary'); ?>
        </form>

        <hr />
        <h2><?php _e('Status', 'nextguard'); ?></h2>
        <?php
        if ($is_connected) {
            echo '<p style="color:green">&#10003; ' . __('Connected via device token. Sync runs daily automatically.', 'nextguard') . '</p>';
        } elseif ($api_key && $project_id) {
            echo '<p style="color:orange">&#9888; ' . __('Legacy configuration — reconnect using the Device Auth Flow above.', 'nextguard') . '</p>';
        } else {
            echo '<p style="color:orange">&#9888; ' . __('Not configured. Connect above to get started.', 'nextguard') . '</p>';
        }
        ?>
    </div>

    <script>
    (function($) {
        var nonce   = <?php echo wp_json_encode($nonce); ?>;
        var ajaxUrl = <?php echo wp_json_encode(admin_url('admin-ajax.php')); ?>;

        // Toggle connect form for already-connected users
        $('#nextguard-reconnect-link').on('click', function(e) {
            e.preventDefault();
            $('#nextguard-connect-form').show();
        });

        // Step 1: Request activation code
        $('#nextguard-get-code').on('click', function() {
            var apiKey = $('#nextguard_api_key_input').val().trim();
            if (!apiKey) {
                $('#nextguard-step1-error').text('<?php echo esc_js(__('Please enter your API key.', 'nextguard')); ?>').show();
                return;
            }
            $('#nextguard-step1-error').hide();
            $('#nextguard-get-code').prop('disabled', true);
            $('#nextguard-step1-spinner').show();

            $.post(ajaxUrl, {
                action: 'nextguard_request_code',
                nonce:  nonce,
                api_key: apiKey,
            }, function(resp) {
                $('#nextguard-get-code').prop('disabled', false);
                $('#nextguard-step1-spinner').hide();

                if (!resp.success) {
                    $('#nextguard-step1-error').text(resp.data.message || '<?php echo esc_js(__('Request failed.', 'nextguard')); ?>').show();
                    return;
                }

                var code      = resp.data.code;
                var expiresIn = resp.data.expiresIn || 900;
                var minutes   = Math.round(expiresIn / 60);

                $('#nextguard-code-display').text(code);
                $('#nextguard-code-expiry').text('<?php echo esc_js(__('Expires in', 'nextguard')); ?> ' + minutes + ' <?php echo esc_js(__('minutes', 'nextguard')); ?>');
                $('#nextguard-step-1').hide();
                $('#nextguard-step-2').show();
            }).fail(function() {
                $('#nextguard-get-code').prop('disabled', false);
                $('#nextguard-step1-spinner').hide();
                $('#nextguard-step1-error').text('<?php echo esc_js(__('Network error. Please try again.', 'nextguard')); ?>').show();
            });
        });

        // Step 2: Poll status
        $('#nextguard-poll-btn').on('click', function() {
            $('#nextguard-step2-error').hide();
            $('#nextguard-poll-btn').prop('disabled', true);
            $('#nextguard-step2-spinner').show();

            function poll() {
                $.post(ajaxUrl, {
                    action: 'nextguard_poll_status',
                    nonce:  nonce,
                }, function(resp) {
                    if (!resp.success) {
                        $('#nextguard-poll-btn').prop('disabled', false);
                        $('#nextguard-step2-spinner').hide();
                        var msg = (resp.data && resp.data.message) ? resp.data.message : '<?php echo esc_js(__('Error checking status.', 'nextguard')); ?>';
                        $('#nextguard-step2-error').text(msg).show();
                        return;
                    }

                    var status = resp.data.status;

                    if (status === 'authorized') {
                        // Reload to show the connected state
                        window.location.reload();
                        return;
                    }

                    if (status === 'expired') {
                        $('#nextguard-poll-btn').prop('disabled', false);
                        $('#nextguard-step2-spinner').hide();
                        $('#nextguard-step2-error').text('<?php echo esc_js(__('Code expired. Please go back and request a new one.', 'nextguard')); ?>').show();
                        setTimeout(function() {
                            $('#nextguard-step-2').hide();
                            $('#nextguard-step-1').show();
                        }, 3000);
                        return;
                    }

                    // Still pending — poll again in 3 seconds
                    setTimeout(poll, 3000);
                }).fail(function() {
                    // Network hiccup — retry
                    setTimeout(poll, 3000);
                });
            }

            poll();
        });
    })(jQuery);
    </script>
    <?php
}
