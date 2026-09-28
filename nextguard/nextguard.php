<?php
/**
 * Plugin Name: NextGuard Security Scanner
 * Plugin URI:  https://nextguardhq.com
 * Description: Syncs your installed plugins and themes to NextGuard for continuous CVE monitoring.
 * Version:     2.0.0
 * Author:      NextGuard
 * Author URI:  https://nextguardhq.com
 * License:     GPLv2 or later
 * Text Domain: nextguard
 */

defined('ABSPATH') || exit;

define('NEXTGUARD_VERSION',          '2.0.0');
// API base — defaults to production. To point at a local/staging dashboard for
// testing, define NEXTGUARD_API_BASE in wp-config.php BEFORE WordPress loads
// plugins, e.g. define('NEXTGUARD_API_BASE', 'https://your-tunnel.ngrok.io');
// The override lives only in the site's wp-config — this file always ships the
// production default, so the published plugin is always pointed at production.
if (!defined('NEXTGUARD_API_BASE')) {
    define('NEXTGUARD_API_BASE', 'https://nextguardhq.com');
}
define('NEXTGUARD_ACTIVATE_URL',     NEXTGUARD_API_BASE . '/api/v1/auth/activate');
define('NEXTGUARD_STATUS_URL',       NEXTGUARD_API_BASE . '/api/v1/auth/activate');
define('NEXTGUARD_API_URL',          NEXTGUARD_API_BASE . '/api/v1/cms/sync');
define('NEXTGUARD_OPTION_API_KEY',   'nextguard_api_key');
define('NEXTGUARD_OPTION_TOKEN',     'nextguard_token');       // device token (ng_dev_...)
define('NEXTGUARD_OPTION_PROJECT_ID','nextguard_project_id');
define('NEXTGUARD_OPTION_ENV_TOKEN', 'nextguard_environment_token'); // opcional (vs_pe_*): ata el sync a un ambiente  // auto-filled after auth
define('NEXTGUARD_CRON_HOOK',        'nextguard_sync_cron');

// ── Activation / deactivation ────────────────────────────────────────────────

register_activation_hook(__FILE__, 'nextguard_activate');
register_deactivation_hook(__FILE__, 'nextguard_deactivate');

// Load translations (es, pt, fr, de, nl, ja, zh, hi) from /languages.
add_action('plugins_loaded', function () {
    load_plugin_textdomain('nextguard', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

// "Scan / Settings" action link on the Plugins list so users find the page.
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'nextguard_action_links');
function nextguard_action_links($links) {
    $url = admin_url('options-general.php?page=nextguard');
    array_unshift(
        $links,
        '<a href="' . esc_url($url) . '" style="font-weight:600;color:#ef4444;">' . __('Scan now', 'nextguard') . '</a>'
    );
    return $links;
}

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

/**
 * Enmascara un valor sensible para el reporte: deja los 2 primeros y tapa el
 * resto. El nombre completo de un usuario no tiene por qué salir del sitio.
 */
function nextguard_mask(string $v): string {
    $v = trim($v);
    if ($v === '') return '';
    if (strlen($v) <= 2) return $v[0] . '*';
    return substr($v, 0, 2) . str_repeat('*', min(6, strlen($v) - 2));
}

/**
 * Auditoría interna del sitio WordPress — lo que un escaneo de superficie no ve.
 *
 * Equivalente al `SecurityAudit` del módulo Drupal, adaptado a WordPress. Cada
 * hallazgo lleva un `id` ESTABLE: es la clave por la que el servidor deduplica
 * entre syncs, así que un mismo problema no se apila. Nunca sale contenido
 * sensible (contraseñas, claves, contenido de wp-config): sólo el hecho y, como
 * mucho, un nombre enmascarado.
 *
 * @param array<string,array> $all_plugins
 * @param array<int,string>   $active_slugs
 * @param WP_Theme            $theme
 * @return array{findings:array<int,array>,meta:array}
 */
function nextguard_collect_audit(array $all_plugins, array $active_slugs, $theme): array {
    $f = [];
    $add = static function (string $id, string $sev, string $title, string $detail, string $rem = '', array $ctx = []) use (&$f) {
        $f[] = array_filter([
            'id' => $id, 'severity' => $sev, 'title' => $title,
            'detail' => $detail, 'remediation' => $rem, 'context' => $ctx,
        ], static fn ($v) => $v !== '' && $v !== []);
    };

    // ── Configuración ────────────────────────────────────────────────────────
    if (defined('WP_DEBUG') && WP_DEBUG) {
        $display = defined('WP_DEBUG_DISPLAY') ? WP_DEBUG_DISPLAY : true;
        $add('wp:debug-on', $display ? 'MEDIUM' : 'LOW',
            'WP_DEBUG está activo' . ($display ? ' y muestra errores en pantalla' : ''),
            'El modo debug filtra rutas del servidor, versiones y trazas de error a cualquier visitante cuando se muestran en pantalla.',
            'Poné WP_DEBUG en false en producción (wp-config.php). Si necesitás depurar, usá WP_DEBUG_LOG y WP_DEBUG_DISPLAY=false.');
    }
    // Editor de plugins/temas: si está habilitado, un admin comprometido tiene RCE directa.
    if (!defined('DISALLOW_FILE_EDIT') || !DISALLOW_FILE_EDIT) {
        $add('wp:file-edit-enabled', 'HIGH',
            'El editor de archivos del panel está habilitado',
            'Con el editor de plugins/temas activo, cualquiera que consiga acceso de administrador puede ejecutar código PHP en el servidor sin tocar el hosting.',
            "Agregá define('DISALLOW_FILE_EDIT', true); a wp-config.php.");
    }
    if (!defined('DISALLOW_FILE_MODS') || !DISALLOW_FILE_MODS) {
        $add('wp:file-mods-enabled', 'LOW',
            'Instalación/actualización de plugins desde el panel habilitada',
            'Permite instalar plugins y temas desde el panel — superficie extra si una cuenta admin se compromete.',
            "Opcional y estricto: define('DISALLOW_FILE_MODS', true); bloquea toda modificación de archivos desde el panel.");
    }
    if (!defined('FORCE_SSL_ADMIN') || !FORCE_SSL_ADMIN) {
        $add('wp:no-force-ssl-admin', 'LOW',
            'El panel no fuerza HTTPS',
            'Sin FORCE_SSL_ADMIN, las credenciales de administración pueden viajar sin cifrar si alguien llega por http://.',
            "Agregá define('FORCE_SSL_ADMIN', true); a wp-config.php.");
    }
    // Registro abierto de usuarios + rol por defecto.
    if ((int) get_option('users_can_register') === 1) {
        $role = (string) get_option('default_role', 'subscriber');
        $risky = in_array($role, ['administrator', 'editor', 'author'], true);
        $add('wp:open-registration', $risky ? 'HIGH' : 'LOW',
            "Registro de usuarios abierto (rol por defecto: {$role})",
            $risky
                ? "Cualquiera puede registrarse y obtiene el rol «{$role}», que puede publicar o administrar contenido."
                : 'Cualquiera puede crear una cuenta. Con rol subscriber el riesgo es bajo, pero suma superficie de spam/enumeración.',
            $risky ? 'Cambiá el rol por defecto a subscriber, o cerrá el registro si no lo necesitás.' : 'Revisá si el registro abierto es necesario.');
    }
    // XML-RPC: vector clásico de fuerza bruta amplificada y pingback DDoS.
    if (function_exists('apply_filters') && apply_filters('xmlrpc_enabled', true)) {
        $add('wp:xmlrpc-enabled', 'LOW',
            'XML-RPC está habilitado',
            'xmlrpc.php permite amplificar intentos de login (system.multicall) y usar el sitio para pingback DDoS.',
            'Si no usás la app móvil de WordPress ni Jetpack, deshabilitá XML-RPC (filtro xmlrpc_enabled o a nivel servidor).');
    }

    // ── Versiones / superficie ───────────────────────────────────────────────
    if (!function_exists('get_core_updates')) {
        require_once ABSPATH . 'wp-admin/includes/update.php';
    }
    $core = function_exists('get_core_updates') ? get_core_updates() : [];
    if (is_array($core) && !empty($core) && isset($core[0]->response) && $core[0]->response === 'upgrade') {
        $add('wp:core-outdated', 'HIGH',
            'El núcleo de WordPress está desactualizado',
            'Hay una versión más nueva de WordPress disponible. Las versiones viejas acumulan CVEs conocidos con exploits públicos.',
            'Actualizá el núcleo desde Escritorio → Actualizaciones.',
            ['installed' => get_bloginfo('version')]);
    }
    $plugin_updates = function_exists('get_plugin_updates') ? get_plugin_updates() : [];
    if (is_array($plugin_updates) && count($plugin_updates) > 0) {
        $add('wp:plugins-outdated', count($plugin_updates) >= 3 ? 'HIGH' : 'MEDIUM',
            count($plugin_updates) . ' plugin(s) con actualización pendiente',
            'Los plugins son la vía de entrada más común a un WordPress. Cada plugin desactualizado puede tener un CVE con exploit público.',
            'Actualizá los plugins desde Escritorio → Actualizaciones.',
            ['count' => count($plugin_updates)]);
    }
    $theme_updates = function_exists('get_theme_updates') ? get_theme_updates() : [];
    if (is_array($theme_updates) && count($theme_updates) > 0) {
        $add('wp:themes-outdated', 'LOW',
            count($theme_updates) . ' tema(s) con actualización pendiente',
            'Un tema desactualizado —incluso inactivo— puede tener vulnerabilidades explotables.',
            'Actualizá los temas, y borrá los que no uses.',
            ['count' => count($theme_updates)]);
    }
    // Plugins inactivos: código que sigue en disco y a veces es alcanzable.
    $inactive = 0;
    foreach ($all_plugins as $path => $_d) {
        if (!in_array($path, $active_slugs, true)) $inactive++;
    }
    if ($inactive > 0) {
        $add('wp:inactive-plugins', 'INFO',
            "{$inactive} plugin(s) instalado(s) pero inactivo(s)",
            'Un plugin inactivo sigue en el servidor: su código puede ser alcanzable directamente por URL y no recibe la misma atención de actualización.',
            'Borrá los plugins que no uses (no alcanza con desactivarlos).',
            ['count' => $inactive]);
    }

    // ── Usuarios ─────────────────────────────────────────────────────────────
    if (function_exists('get_users')) {
        // Usuario con login "admin": el objetivo por defecto de todo ataque de fuerza bruta.
        $admin_user = get_users(['login' => 'admin', 'number' => 1, 'fields' => ['ID']]);
        if (!empty($admin_user)) {
            $add('wp:admin-username', 'MEDIUM',
                'Existe un usuario con el nombre «admin»',
                'El login «admin» es el primero que prueba cualquier ataque de fuerza bruta — le regala la mitad del trabajo.',
                'Creá un administrador nuevo con otro nombre y eliminá el usuario «admin» (reasignando su contenido).');
        }
        // Cantidad de administradores.
        $admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login']]);
        $n_admins = is_array($admins) ? count($admins) : 0;
        if ($n_admins > 3) {
            $add('wp:many-admins', 'LOW',
                "{$n_admins} cuentas con rol administrador",
                'Cada administrador es una llave maestra del sitio. Cuantas más, mayor la superficie: basta comprometer una.',
                'Revisá si todas necesitan rol administrador; bajá a editor las que no.',
                ['count' => $n_admins]);
        }
        // Enumeración de autor: display_name == user_login facilita la fuerza bruta.
        $exposed = [];
        foreach ((array) $admins as $a) {
            $u = get_userdata($a->ID);
            if ($u && strcasecmp($u->display_name, $u->user_login) === 0) {
                $exposed[] = nextguard_mask($u->user_login);
            }
        }
        if (!empty($exposed)) {
            $add('wp:author-enumeration', 'LOW',
                count($exposed) . ' admin(s) con nombre visible igual al login',
                'Cuando el «nombre público» coincide con el usuario de login, la página de autor revela credenciales válidas para fuerza bruta.',
                'Cambiá el «Mostrar este nombre públicamente» para que difiera del nombre de usuario.',
                ['users' => $exposed]);
        }
    }

    // ── Filesystem ───────────────────────────────────────────────────────────
    $wp_config = ABSPATH . 'wp-config.php';
    if (@file_exists($wp_config)) {
        $perms = @fileperms($wp_config);
        if ($perms !== false && ($perms & 0o044)) { // legible por grupo u otros
            $add('wp:wp-config-perms', 'HIGH',
                'wp-config.php es legible por otros usuarios del servidor',
                'wp-config.php contiene las credenciales de la base de datos y las claves de seguridad. Si otros usuarios del servidor pueden leerlo, esas credenciales están expuestas.',
                'Ajustá los permisos a 640 o 600 (chmod 600 wp-config.php).',
                ['mode' => substr(sprintf('%o', $perms), -4)]);
        }
    }

    return [
        'findings' => $f,
        'meta' => ['version' => NEXTGUARD_VERSION, 'ran' => [
            'configuration', 'versions', 'users', 'filesystem',
        ]],
    ];
}

/**
 * Integridad de un plugin de wordpress.org (spec 048): compara el md5 de cada
 * archivo con los checksums oficiales de su versión — el mismo origen que usa
 * `wp plugin verify-checksums`. Un plugin sin checksums publicados (premium,
 * propio) es «unverifiable», nunca «verified». Resultado en caché 24 h.
 *
 * @return array{integrity:string, modifiedFiles:array<int,string>}|null  null = sin presupuesto
 */
function nextguard_plugin_integrity(string $slug, string $version) {
    $unverifiable = ['integrity' => 'unverifiable', 'modifiedFiles' => []];
    if ($slug === '' || $version === '' || !function_exists('wp_remote_get') || !defined('WP_PLUGIN_DIR')) return $unverifiable;
    $cache_key = 'ng_ck_' . md5($slug . '@' . $version);
    $cached = get_transient($cache_key);
    if (is_array($cached)) return $cached;

    $url  = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json';
    $resp = wp_remote_get($url, ['timeout' => 5]);
    $day  = defined('DAY_IN_SECONDS') ? DAY_IN_SECONDS : 86400;
    if (is_wp_error($resp) || (int) wp_remote_retrieve_response_code($resp) !== 200) {
        set_transient($cache_key, $unverifiable, $day);
        return $unverifiable;
    }
    $data = json_decode(wp_remote_retrieve_body($resp), true);
    if (!is_array($data) || !isset($data['files']) || !is_array($data['files'])) {
        set_transient($cache_key, $unverifiable, $day);
        return $unverifiable;
    }
    $base     = rtrim(WP_PLUGIN_DIR, '/') . '/' . $slug;
    $modified = [];
    foreach ($data['files'] as $file => $sums) {
        if (!is_string($file) || strpos($file, '..') !== false) continue;
        $path = $base . '/' . $file;
        if (!is_file($path)) continue; // un archivo que falta no es una modificación
        $md5      = md5_file($path);
        $expected = is_array($sums) ? ($sums['md5'] ?? null) : null;
        $ok       = is_array($expected) ? in_array($md5, $expected, true) : ($md5 === $expected);
        if (!$ok) $modified[] = sanitize_text_field($file);
        if (count($modified) >= 200) break;
    }
    $result = ['integrity' => $modified ? 'modified' : 'verified', 'modifiedFiles' => $modified];
    set_transient($cache_key, $result, $day);
    return $result;
}

function nextguard_sync() {
    $auth_key   = nextguard_effective_key();
    $project_id = get_option(NEXTGUARD_OPTION_PROJECT_ID, '');

    // Anonymous Live Scan keys (vs_pk_anon_) bind to an ephemeral project
    // server-side, so no local project_id is required.
    $is_anon = strpos($auth_key, 'vs_pk_anon_') === 0;
    if (empty($auth_key) || (empty($project_id) && !$is_anon)) return;

    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins  = get_plugins();
    $active_slugs = (array) get_option('active_plugins', []);
    $components   = [];

    // Spec 048: presupuesto de verificación de archivos por sync (los resultados
    // quedan en caché 24 h, así que un sitio grande completa la verificación en
    // pocos syncs sin colgar ninguno).
    $integrity_budget_s = 20.0;
    $integrity_max      = 40;
    $integrity_started  = microtime(true);
    $integrity_done     = 0;
    $complete           = true;

    foreach ($all_plugins as $path => $data) {
        $dir  = dirname($path);
        $slug = ($dir && $dir !== '.') ? $dir : basename($path, '.php');
        $component = [
            'name'    => sanitize_text_field($data['Name']),
            'slug'    => $slug,
            'version' => sanitize_text_field($data['Version']),
            'type'    => 'plugin',
            // Inactivo no es inexistente: se manda igual, marcado.
            'active'  => in_array($path, $active_slugs, true),
            'path'    => 'wp-content/plugins/' . (($dir && $dir !== '.') ? $dir : basename($path)),
        ];
        if ($dir && $dir !== '.' && $integrity_done < $integrity_max && (microtime(true) - $integrity_started) < $integrity_budget_s) {
            $integrity = nextguard_plugin_integrity($slug, (string) $component['version']);
            $component['integrity']     = $integrity['integrity'];
            $component['modifiedFiles'] = $integrity['modifiedFiles'];
            $integrity_done++;
        }
        $components[] = $component;
    }

    // Temas: TODOS los instalados, con su estado (spec 048). Un tema inactivo
    // también deja archivos alcanzables.
    $theme = wp_get_theme();
    $active_stylesheet = $theme->get_stylesheet();
    $parent_stylesheet = $theme->parent() ? $theme->parent()->get_stylesheet() : null;
    $themes = function_exists('wp_get_themes') ? (array) wp_get_themes() : [];
    if (empty($themes)) {
        $themes = [$active_stylesheet => $theme];
        if ($theme->parent()) $themes[$parent_stylesheet] = $theme->parent();
    }
    foreach ($themes as $stylesheet => $t) {
        $components[] = [
            'name'    => sanitize_text_field((string) $t->get('Name')),
            'slug'    => (string) $stylesheet,
            'version' => sanitize_text_field((string) $t->get('Version')),
            'type'    => 'theme',
            'active'  => ($stylesheet === $active_stylesheet || $stylesheet === $parent_stylesheet),
            'path'    => 'wp-content/themes/' . $stylesheet,
        ];
    }

    // Auditoría interna — ADITIVA. Si algo falla, se omite; nunca rompe el sync
    // (mismo criterio que el módulo Drupal). Es lo que un escaneo de superficie
    // NO puede ver desde afuera: config del sitio, usuarios, permisos.
    $audit = null;
    try {
        $audit = nextguard_collect_audit($all_plugins, $active_slugs, $theme);
    } catch (\Throwable $e) {
        $audit = null; // aditivo: la ausencia de auditoría no invalida el inventario
    }

    $payload = [
        'projectId'  => $project_id,
        'cmsType'    => 'wordpress',
        'cmsVersion' => get_bloginfo('version'),
        'phpVersion' => PHP_VERSION,
        'siteUrl'    => home_url(),
        'components' => $components,
        'collector'  => ['version' => NEXTGUARD_VERSION, 'complete' => $complete],
    ];
    $env_token = (string) get_option(NEXTGUARD_OPTION_ENV_TOKEN, '');
    if ($env_token !== '' && strpos($env_token, 'vs_pe_') === 0) {
        $payload['environmentToken'] = $env_token;
    }
    if ($audit !== null) {
        $payload['audit'] = $audit;
    }
    $body = wp_json_encode($payload);

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
        'timeout'  => 20,
        // Anonymous keys: block to capture the teaser preview the server returns,
        // so we can show vulnerabilities + a register CTA right here in the admin.
        'blocking' => $is_anon,
    ]);

    if (!is_wp_error($response)) {
        update_option('nextguard_last_sync', current_time('mysql'));
        if ($is_anon) {
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (is_array($data) && isset($data['preview'])) {
                update_option('nextguard_last_preview', wp_json_encode($data['preview']));
                update_option('nextguard_register_url', $data['registerUrl'] ?? 'https://nextguardhq.com/register');
                update_option('nextguard_syncs_remaining', isset($data['syncsRemaining']) ? intval($data['syncsRemaining']) : null);
                update_option('nextguard_max_syncs', isset($data['maxSyncs']) ? intval($data['maxSyncs']) : null);
                // Scan date — prefer the server timestamp, fall back to local time.
                update_option('nextguard_last_scan', !empty($data['scannedAt']) ? $data['scannedAt'] : current_time('mysql'));
                // Plan upgrade links (origin-aware) for the "create account" panel.
                if (!empty($data['plans']) && is_array($data['plans'])) {
                    update_option('nextguard_plan_links', wp_json_encode($data['plans']));
                }
            }
        }
    }
}

// ── Plans: load live from the dashboard (cached), with a static fallback ─────
// Keeps prices/benefits in sync with the website — no hardcoded pricing here.

function nextguard_fetch_plans($ng_base, $plan_links = array()) {
    $locale    = function_exists('get_locale') ? get_locale() : 'en_US';
    $cache_key = 'nextguard_plans_' . substr(md5($ng_base . '|' . $locale), 0, 12);
    $cached    = get_transient($cache_key);
    if (is_array($cached) && !empty($cached)) {
        return $cached;
    }

    $url  = rtrim($ng_base, '/') . '/api/public/plans?keys=free,monitoring,starter&locale=' . rawurlencode($locale);
    $resp = wp_remote_get($url, array('timeout' => 8, 'headers' => array('ngrok-skip-browser-warning' => '1')));
    if (!is_wp_error($resp) && wp_remote_retrieve_response_code($resp) === 200) {
        $data = json_decode(wp_remote_retrieve_body($resp), true);
        if (is_array($data) && !empty($data['plans']) && is_array($data['plans'])) {
            set_transient($cache_key, $data['plans'], HOUR_IN_SECONDS);
            return $data['plans'];
        }
    }

    // Fallback (endpoint unreachable) — static set, still localized by the plugin.
    $pl = function ($k, $def) use ($plan_links) { return isset($plan_links[$k]) ? $plan_links[$k] : $def; };
    return array(
        array(
            'key' => 'free', 'name' => __('Free', 'nextguard'), 'priceDisplay' => '$0', 'period' => '',
            'href' => $pl('free', rtrim($ng_base, '/') . '/register'),
            'cta' => __('Create free account', 'nextguard'), 'highlighted' => false,
            'features' => array(
                __('Full vulnerability report (no blur)', 'nextguard'),
                __('1 monitored project', 'nextguard'),
                __('CVE database access', 'nextguard'),
            ),
        ),
        array(
            'key' => 'monitoring', 'name' => __('Monitoring', 'nextguard'), 'priceDisplay' => '$3', 'period' => '/mo',
            'href' => $pl('monitoring', rtrim($ng_base, '/') . '/checkout/monitoring'),
            'cta' => __('Get Monitoring', 'nextguard'), 'highlighted' => true,
            'features' => array(
                __('Continuous automatic re-scans', 'nextguard'),
                __('Email alerts on new CVEs', 'nextguard'),
                __('Unlimited scans, no expiry', 'nextguard'),
            ),
        ),
        array(
            'key' => 'starter', 'name' => __('Starter', 'nextguard'), 'priceDisplay' => '$7', 'period' => '/mo',
            'href' => $pl('starter', rtrim($ng_base, '/') . '/checkout/starter'),
            'cta' => __('Get Starter', 'nextguard'), 'highlighted' => false,
            'features' => array(
                __('Everything in Monitoring', 'nextguard'),
                __('Multiple projects & environments', 'nextguard'),
                __('Scan history & auto-patching', 'nextguard'),
            ),
        ),
    );
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

    // Anonymous Live Scan keys (vs_pk_anon_) skip the device-authorization flow:
    // there is no account to approve a code in. We sync immediately — the server
    // binds the data to the ephemeral project behind the key — and the home widget
    // picks up the result by polling.
    if (strpos($api_key, 'vs_pk_anon_') === 0) {
        nextguard_sync();
        wp_send_json_success([
            'anon'    => true,
            'message' => __('Connected. Syncing your site… check the scan on the page where you got this key.', 'nextguard'),
        ]);
    }

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
    // Spec 048: token de ambiente (opcional). Con él, el inventario de este
    // sitio se asocia al ambiente correcto aunque su URL no coincida.
    // Grupo propio: si compartiera grupo con la API key, guardar este
    // formulario por options.php dejaría la clave en blanco.
    register_setting('nextguard_env_settings', NEXTGUARD_OPTION_ENV_TOKEN, [
        'sanitize_callback' => 'nextguard_sanitize_env_token',
    ]);
}

function nextguard_sanitize_env_token($value): string {
    $v = trim(sanitize_text_field((string) $value));
    return preg_match('/^vs_pe_[a-f0-9]{64}$/', $v) ? $v : '';
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
    $is_anon      = !empty($api_key) && strpos($api_key, 'vs_pk_anon_') === 0;
    // Links point at the configured base (the tunnel locally, production when published).
    $ng_base      = defined('NEXTGUARD_API_BASE') ? rtrim(NEXTGUARD_API_BASE, '/') : 'https://nextguardhq.com';
    $is_connected = !empty($token) && !empty($project_id);
    $nonce        = wp_create_nonce('nextguard_ajax');

    // Legacy reconnect notice: has api_key + project_id but no device token
    $show_reconnect = (!empty($api_key) && !empty($project_id) && empty($token));
    ?>
    <div class="wrap">
        <h1><span style="color:#ef4444">&#9632;</span> NextGuard Security Scanner</h1>
        <p><?php printf(__('Automatically syncs your installed plugins and themes to <a href="%s" target="_blank">NextGuard</a> for continuous CVE monitoring.', 'nextguard'), esc_url($ng_base)); ?></p>

        <?php if ($is_anon): ?>
        <div style="background:#eff6ff;border:1px solid #bfdbfe;padding:16px 20px;border-radius:6px;margin:20px 0;max-width:760px;">
            <p style="margin:0 0 6px;font-weight:700;color:#1d4ed8;">&#128270; <?php _e('Free scan active — no account needed', 'nextguard'); ?></p>
            <p style="margin:0;color:#374151;font-size:14px;line-height:1.6;">
                <?php _e('You are running a <strong>free, anonymous scan</strong>. Below you can see the vulnerabilities detected on your site right now. <strong>Register a free NextGuard account</strong> to unlock the full list and get continuous monitoring with email alerts.', 'nextguard'); ?>
            </p>
            <p style="margin:8px 0 0;color:#6b7280;font-size:12px;">
                <?php _e('Have a paid NextGuard account? You can connect it with your API key using the device-authorization flow below — that links this site to a project for ongoing monitoring.', 'nextguard'); ?>
            </p>
        </div>
        <?php endif; ?>

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
                <h2><?php _e('Connect & scan', 'nextguard'); ?></h2>
                <p style="max-width:780px;color:#374151;"><?php _e('Paste an API key to scan this site. <strong>No paid plan required.</strong>', 'nextguard'); ?></p>
                <ul style="max-width:780px;color:#374151;list-style:disc;margin:6px 0 4px 22px;">
                    <li><?php printf(__('<strong>Free, no account:</strong> open <a href="%s/#scan" target="_blank">nextguardhq.com → Free scan</a>, run the free CMS scan and copy the key it gives you — it works for a few scans, no sign-up.', 'nextguard'), esc_url($ng_base)); ?></li>
                    <li><?php printf(__('<strong>With a NextGuard account:</strong> paste your key from <a href="%s/account" target="_blank">Account → API Keys</a> to link this site to a project for continuous monitoring.', 'nextguard'), esc_url($ng_base)); ?></li>
                </ul>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="nextguard_api_key_input"><?php _e('API Key', 'nextguard'); ?></label></th>
                        <td>
                            <input type="password" id="nextguard_api_key_input"
                                   value="<?php echo esc_attr($api_key); ?>"
                                   class="regular-text" placeholder="vs_pk_..." />
                            <p class="description"><?php _e('Free keys start with <code>vs_pk_anon_</code> (temporary). Account keys start with <code>vs_pk_</code>.', 'nextguard'); ?></p>
                        </td>
                    </tr>
                </table>
                <button type="button" id="nextguard-get-code" class="button button-primary"><?php _e('Connect &amp; scan', 'nextguard'); ?></button>
                <span id="nextguard-step1-spinner" style="display:none;margin-left:8px;" class="spinner is-active"></span>
                <p id="nextguard-step1-error" style="color:#dc2626;display:none;"></p>
            </div>

            <!-- ── Step 2: Show code + poll ── -->
            <div id="nextguard-step-2" style="display:none;background:#fffbeb;border:1px solid #fcd34d;padding:16px 20px;border-radius:6px;margin:16px 0;">
                <p style="margin:0 0 8px;"><?php printf(__('Go to <a href="%s/account" target="_blank">nextguardhq.com/account → Connected Devices</a> and enter this code:', 'nextguard'), esc_url($ng_base)); ?></p>
                <p style="font-size:28px;font-weight:700;letter-spacing:4px;color:#1e293b;margin:12px 0;" id="nextguard-code-display"></p>
                <p style="color:#6b7280;font-size:12px;margin:0 0 12px;" id="nextguard-code-expiry"></p>
                <button type="button" id="nextguard-poll-btn" class="button button-primary"><?php _e("I've authorized it — Continue", 'nextguard'); ?></button>
                <span id="nextguard-step2-spinner" style="display:none;margin-left:8px;" class="spinner is-active"></span>
                <p id="nextguard-step2-error" style="color:#dc2626;display:none;"></p>
            </div>

        </div><!-- #nextguard-connect-form -->

        <?php
        // ── Vulnerability preview (teaser) — same results shown on the dashboard ──
        $preview_raw  = get_option('nextguard_last_preview', '');
        $preview      = $preview_raw ? json_decode($preview_raw, true) : null;
        $register_url = get_option('nextguard_register_url', 'https://nextguardhq.com/register');
        $syncs_left   = get_option('nextguard_syncs_remaining', null);
        $scan_date    = get_option('nextguard_last_scan', $last_sync);
        $plan_links_raw = get_option('nextguard_plan_links', '');
        $plan_links   = $plan_links_raw ? json_decode($plan_links_raw, true) : array();
        if (!is_array($plan_links)) $plan_links = array();
        // Plans are loaded LIVE from the dashboard so prices/benefits stay in sync.
        // Falls back to a static set if the endpoint is unreachable.
        $ng_plans = nextguard_fetch_plans($ng_base, $plan_links);
        if (is_array($preview) && !empty($preview['available']) && !empty($preview['summary']) && intval($preview['summary']['total']) > 0):
            $s = $preview['summary'];
        ?>
        <hr />
        <h2><?php _e('Vulnerabilities detected on your site', 'nextguard'); ?></h2>
        <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start;max-width:1320px;">
          <div style="flex:1 1 560px;min-width:320px;">
            <p style="font-size:20px;font-weight:700;color:#dc2626;margin:0 0 4px;"><?php printf(__('%d vulnerabilities found', 'nextguard'), intval($s['total'])); ?></p>
            <?php if ($scan_date): ?>
            <p style="margin:0 0 10px;color:#6b7280;font-size:12px;">&#128337; <?php printf(__('Last scan: %s', 'nextguard'), esc_html($scan_date)); ?></p>
            <?php endif; ?>
            <p style="margin:0 0 12px;font-family:monospace;font-size:13px;">
                <span style="color:#dc2626;"><?php echo intval($s['critical']); ?> CRITICAL</span> &middot;
                <span style="color:#ea580c;"><?php echo intval($s['high']); ?> HIGH</span> &middot;
                <span style="color:#ca8a04;"><?php echo intval($s['medium']); ?> MEDIUM</span> &middot;
                <span style="color:#65a30d;"><?php echo intval($s['low'] ?? 0); ?> LOW</span>
            </p>
            <table class="widefat striped" style="max-width:920px;">
                <thead><tr>
                    <th style="width:90px;"><?php _e('Severity', 'nextguard'); ?></th>
                    <th><?php _e('Component', 'nextguard'); ?></th>
                    <th style="width:110px;"><?php _e('Installed', 'nextguard'); ?></th>
                    <th><?php _e('Vulnerability', 'nextguard'); ?></th>
                    <th style="width:100px;"><?php _e('Fixed in', 'nextguard'); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach (($preview['shown'] ?? []) as $v):
                    $sev = strtoupper($v['severity'] ?? '—');
                    $sevColor = $sev === 'CRITICAL' ? '#dc2626' : ($sev === 'HIGH' ? '#ea580c' : ($sev === 'MEDIUM' ? '#ca8a04' : '#65a30d'));
                ?>
                    <tr>
                        <td><span style="font-weight:700;font-size:11px;color:<?php echo $sevColor; ?>;"><?php echo esc_html($sev); ?></span></td>
                        <td><strong><?php echo esc_html($v['componentName'] ?? $v['component'] ?? '—'); ?></strong></td>
                        <td><code><?php echo esc_html($v['installedVersion'] ?? '—'); ?></code></td>
                        <td><?php echo esc_html($v['title'] ?? ($v['cveId'] ?? '—')); ?></td>
                        <td><?php echo esc_html($v['fixedIn'] ?? '—'); ?></td>
                    </tr>
                <?php endforeach; ?>
                <?php if (!empty($preview['hidden']) && intval($preview['hidden']) > 0): for ($i = 0; $i < min(3, intval($preview['hidden'])); $i++): ?>
                    <tr style="filter:blur(3px);user-select:none;">
                        <td><span style="font-weight:700;font-size:11px;color:#dc2626;">HIGH</span></td>
                        <td>&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;</td>
                        <td>&#9608;.&#9608;.&#9608;</td>
                        <td>&#9608;&#9608;&#9608;&#9608; &#9608;&#9608;&#9608; &#9608;&#9608;&#9608;&#9608;&#9608;&#9608; &#9608;&#9608;&#9608;&#9608;</td>
                        <td>&#9608;.&#9608;.&#9608;</td>
                    </tr>
                <?php endfor; endif; ?>
                </tbody>
            </table>
            <?php if (!empty($preview['hidden']) && intval($preview['hidden']) > 0): ?>
                <p style="font-weight:600;color:#b45309;margin:12px 0 0;"><?php printf(__('+%d more vulnerabilities hidden — register free to see the full report.', 'nextguard'), intval($preview['hidden'])); ?></p>
            <?php endif; ?>
            <p style="margin:14px 0 0;">
                <a href="<?php echo esc_url($register_url); ?>" target="_blank" class="button button-primary button-hero"><?php _e('Register free for the full report + continuous monitoring', 'nextguard'); ?></a>
            </p>
            <?php if ($syncs_left !== null && $syncs_left !== ''): ?>
                <p style="margin:10px 0 0;color:#6b7280;font-size:12px;">&#9432; <?php printf(__('This free key has %d scan(s) left and expires in 2 hours. When it runs out, generate a new free key on the home page or register for unlimited continuous monitoring.', 'nextguard'), intval($syncs_left)); ?></p>
            <?php endif; ?>
          </div><!-- /left column -->

          <!-- ── Right column: why create an account + plans (mirrors home pricing) ── -->
          <div style="flex:0 0 340px;min-width:300px;background:#0f172a;border-radius:8px;padding:20px 18px;color:#e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.2);">
            <h3 style="margin:0 0 6px;color:#fff;font-size:16px;"><?php _e('Why connect a NextGuard account?', 'nextguard'); ?></h3>
            <p style="margin:0 0 16px;color:#94a3b8;font-size:12.5px;line-height:1.6;"><?php _e('This free scan only shows a teaser and the key expires in 2 hours. With an account this site becomes a monitored project: the full report, automatic re-scans, and email alerts whenever a new CVE hits your plugins or themes.', 'nextguard'); ?></p>
            <?php foreach ($ng_plans as $p): $hot = !empty($p['highlighted']) || (isset($p['key']) && $p['key'] === 'monitoring'); ?>
            <div style="border:1px solid <?php echo $hot ? '#0ea5e9' : '#1e293b'; ?>;border-radius:6px;padding:12px 14px;margin:0 0 10px;background:#111827;">
              <div style="display:flex;justify-content:space-between;align-items:baseline;margin:0 0 8px;">
                <strong style="font-size:14px;color:#fff;"><?php echo esc_html($p['name']); ?></strong>
                <span style="font-size:13px;color:#38bdf8;font-weight:700;"><?php echo esc_html((isset($p['priceDisplay']) ? $p['priceDisplay'] : (isset($p['price']) ? $p['price'] : '')) . (isset($p['period']) ? $p['period'] : '')); ?></span>
              </div>
              <ul style="list-style:none;margin:0 0 10px;padding:0;font-size:12px;color:#cbd5e1;line-height:1.5;">
                <?php $ng_feats = isset($p['features']) ? $p['features'] : (isset($p['benefits']) ? $p['benefits'] : array()); foreach ($ng_feats as $b): ?>
                <li style="margin:0 0 4px;"><span style="color:#22c55e;">&#10003;</span> <?php echo esc_html($b); ?></li>
                <?php endforeach; ?>
              </ul>
              <a href="<?php echo esc_url($p['href']); ?>" target="_blank" class="button <?php echo $hot ? 'button-primary' : ''; ?>" style="display:block;width:100%;text-align:center;box-sizing:border-box;"><?php echo esc_html($p['cta']); ?></a>
            </div>
            <?php endforeach; ?>
            <p style="margin:12px 0 0;color:#64748b;font-size:11px;line-height:1.5;"><?php _e('Already have an account? Paste your Account key (vs_pk_…) from Account → API Keys above to link this site to an existing project.', 'nextguard'); ?></p>
          </div><!-- /right column -->
        </div><!-- /flex -->
        <?php elseif (is_array($preview) && !empty($preview['available'])): ?>
        <hr />
        <div style="background:#f0fdf4;border:1px solid #86efac;padding:16px 20px;border-radius:6px;margin:12px 0;max-width:760px;">
            <p style="color:#16a34a;font-weight:600;margin:0;">&#10003; <?php _e('No known vulnerabilities found on your site.', 'nextguard'); ?></p>
        </div>
        <?php endif; ?>

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
        <h2><?php _e('Environment', 'nextguard'); ?></h2>
        <p style="max-width:780px;color:#374151;"><?php _e('Optional. Paste the environment token from NextGuard (Project → Environments) so this site\'s inventory is compared with the right environment even if its URL differs.', 'nextguard'); ?></p>
        <form method="post" action="options.php">
            <?php settings_fields('nextguard_env_settings'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="nextguard_environment_token"><?php _e('Environment token', 'nextguard'); ?></label></th>
                    <td>
                        <input type="password" id="nextguard_environment_token" name="<?php echo esc_attr(NEXTGUARD_OPTION_ENV_TOKEN); ?>"
                               value="<?php echo esc_attr((string) get_option(NEXTGUARD_OPTION_ENV_TOKEN, '')); ?>"
                               class="regular-text" placeholder="vs_pe_..." autocomplete="off" />
                        <p class="description"><?php _e('Starts with <code>vs_pe_</code>. Leave empty to match the environment by the site URL.', 'nextguard'); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button(__('Save environment', 'nextguard'), 'secondary'); ?>
        </form>

        <hr />
        <h2><?php _e('Status', 'nextguard'); ?></h2>
        <?php
        if ($is_connected) {
            echo '<p style="color:green">&#10003; ' . __('Connected via device token. Sync runs daily automatically.', 'nextguard') . '</p>';
        } elseif ($is_anon) {
            echo '<p style="color:#2563eb">&#128270; ' . __('Free scan active (no account). Register at NextGuard for continuous monitoring + alerts.', 'nextguard') . '</p>';
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

                // Anonymous / free-account key: no device code — already synced.
                // Reload so the server-rendered vulnerability preview appears.
                if (resp.data && resp.data.anon) {
                    location.reload();
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
