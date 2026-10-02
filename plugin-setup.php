<?php
/**
 * Plugin Name: Security Headers
 * Description: Sets security headers with admin controls for server type, on/off, and report-only mode.
 * Version: 3.0
 * Author: Stormwerx
 */

defined('ABSPATH') || exit;

// ---------------------------------------------------------------------------
// Constants & Options
// ---------------------------------------------------------------------------
define('SWX_SH_OPTION', 'swx_security_headers');
define('SWX_SH_MARKER', 'Stormwerx Security Headers');

function swx_sh_defaults(): array {
    return [
        'enabled'     => true,
        'report_only' => false,
        'server'      => 'nginx',
    ];
}

function swx_sh_options(): array {
    return wp_parse_args((array) get_option(SWX_SH_OPTION, []), swx_sh_defaults());
}

// ---------------------------------------------------------------------------
// Shared: build header values
// ---------------------------------------------------------------------------
function swx_sh_build_permissions(): string {
    $permissions = apply_filters('swx_permissions_policy', [
        'geolocation' => '()',
        'camera'      => '()',
        'microphone'  => '()',
        'payment'     => '()',
        'usb'         => '()',
        'bluetooth'   => '()',
    ]);
    $pp = [];
    foreach ($permissions as $feat => $val) {
        $pp[] = "{$feat}={$val}";
    }
    return implode(', ', $pp);
}

function swx_sh_build_csp(): string {
    $csp = apply_filters('swx_csp_directives', [
        'default-src'               => ["'self'", 'https:', 'data:', 'blob:'],
        'base-uri'                  => ["'self'"],
        'object-src'                => ["'none'"],
        'frame-ancestors'           => ["'self'"],
        'frame-src'                 => ["'self'", 'https:'],
        'img-src'                   => ["'self'", 'https:', 'data:', 'blob:'],
        'font-src'                  => ["'self'", 'https:', 'data:'],
        'script-src'                => ["'self'", 'https:', "'unsafe-inline'", "'unsafe-eval'"],
        'style-src'                 => [
            "'self'", 'https:', "'unsafe-inline'",
            'www.google.com', 'www.gstatic.com', 'www.recaptcha.net',
            'www.googletagmanager.com', 'www.google-analytics.com',
            'www.youtube.com', 'i.ytimg.com', 's.ytimg.com',
            'player.vimeo.com', 'f.vimeocdn.com',
            'hcaptcha.com', 'assets.hcaptcha.com', 'challenges.cloudflare.com',
            'js.stripe.com', 'www.paypal.com', 'www.paypalobjects.com', 'js.squareup.com',
            'fonts.googleapis.com', 'fonts.gstatic.com', 'use.typekit.net', 'p.typekit.net',
            'platform.instagram.com', 'connect.instagram.com', 'platform.twitter.com',
            'cdn.syndication.twimg.com', 'static.xx.fbcdn.net', 'www.tiktok.com',
            'scontent.cdninstagram.com',
            'stormwerxdigital.com', 'stormwerxwp.com',
            'data:',
        ],
        'connect-src'               => ["'self'", 'https:'],
        'upgrade-insecure-requests' => null,
    ]);

    $parts = [];
    foreach ($csp as $dir => $vals) {
        if ($vals === null) {
            $parts[] = $dir;
            continue;
        }
        $parts[] = $dir . ' ' . implode(' ', array_unique(array_filter($vals)));
    }
    return implode('; ', $parts);
}

function swx_sh_hsts_value(): string {
    $max_age = apply_filters('swx_hsts_max_age', 15552000);
    $subs    = apply_filters('swx_hsts_include_subdomains', true);
    $preload = apply_filters('swx_hsts_preload', false);
    $hsts    = "max-age={$max_age}";
    if ($subs)    { $hsts .= '; includeSubDomains'; }
    if ($preload) { $hsts .= '; preload'; }
    return $hsts;
}

// ---------------------------------------------------------------------------
// Nginx mode: PHP headers (fires for all PHP-processed requests)
// ---------------------------------------------------------------------------
add_action('send_headers', function () {
    if (headers_sent()) {
        return;
    }

    $opts = swx_sh_options();

    if (empty($opts['enabled']) || $opts['server'] !== 'nginx') {
        return;
    }

    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: ' . swx_sh_build_permissions());

    if (is_ssl()) {
        header('Strict-Transport-Security: ' . swx_sh_hsts_value());
    }

    $csp_name = !empty($opts['report_only'])
        ? 'Content-Security-Policy-Report-Only'
        : 'Content-Security-Policy';

    header("{$csp_name}: " . swx_sh_build_csp());
}, 10);

// ---------------------------------------------------------------------------
// Apache mode: write / clear .htaccess on option save
// ---------------------------------------------------------------------------
function swx_sh_build_htaccess_lines(array $opts): array {
    $csp_name = !empty($opts['report_only'])
        ? 'Content-Security-Policy-Report-Only'
        : 'Content-Security-Policy';

    return [
        '<IfModule mod_headers.c>',
        '    Header always set X-Frame-Options "SAMEORIGIN"',
        '    Header always set X-Content-Type-Options "nosniff"',
        '    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        '    Header always set Permissions-Policy "' . swx_sh_build_permissions() . '"',
        '    Header always set ' . $csp_name . ' "' . swx_sh_build_csp() . '"',
        '    # HSTS - applied only over HTTPS connections',
        '    Header always set Strict-Transport-Security "' . swx_sh_hsts_value() . '" env=HTTPS',
        '</IfModule>',
    ];
}

function swx_sh_sync_htaccess(array $opts): void {
    $htaccess = ABSPATH . '.htaccess';

    if (!empty($opts['enabled']) && $opts['server'] === 'apache') {
        insert_with_markers($htaccess, SWX_SH_MARKER, swx_sh_build_htaccess_lines($opts));
    } else {
        // Remove markers when disabled or switched to Nginx
        insert_with_markers($htaccess, SWX_SH_MARKER, []);
    }
}

// Sync .htaccess after option is saved
add_action('updated_option', function (string $option, $old, $new) {
    if ($option === SWX_SH_OPTION) {
        swx_sh_sync_htaccess((array) $new);
    }
}, 10, 3);

// Clean up .htaccess on plugin deactivation
register_deactivation_hook(__FILE__, function () {
    insert_with_markers(ABSPATH . '.htaccess', SWX_SH_MARKER, []);
});

// ---------------------------------------------------------------------------
// Admin Settings Page
// ---------------------------------------------------------------------------
add_action('admin_menu', function () {
    add_options_page(
        'Security Headers',
        'Security Headers',
        'manage_options',
        'swx-security-headers',
        'swx_sh_render_page'
    );
});

add_action('admin_init', function () {
    register_setting(SWX_SH_OPTION, SWX_SH_OPTION, [
        'sanitize_callback' => 'swx_sh_sanitize',
        'default'           => swx_sh_defaults(),
    ]);
});

function swx_sh_sanitize(array $input): array {
    return [
        'enabled'     => !empty($input['enabled']),
        'report_only' => !empty($input['report_only']),
        'server'      => in_array($input['server'] ?? '', ['nginx', 'apache'], true)
                            ? $input['server']
                            : 'nginx',
    ];
}

function swx_sh_render_page(): void {
    if (!current_user_can('manage_options')) {
        return;
    }

    $opts     = swx_sh_options();
    $apache   = $opts['server'] === 'apache';
    $htaccess = ABSPATH . '.htaccess';
    ?>
    <div class="wrap">
        <h1>Security Headers</h1>
        <?php settings_errors(SWX_SH_OPTION); ?>

        <form method="post" action="options.php">
            <?php settings_fields(SWX_SH_OPTION); ?>

            <table class="form-table" role="presentation">

                <tr>
                    <th scope="row">Web Server</th>
                    <td>
                        <fieldset>
                            <label style="margin-right:20px">
                                <input type="radio" name="<?= SWX_SH_OPTION ?>[server]" value="nginx"
                                    <?php checked($opts['server'], 'nginx'); ?>>
                                Nginx
                            </label>
                            <label>
                                <input type="radio" name="<?= SWX_SH_OPTION ?>[server]" value="apache"
                                    <?php checked($opts['server'], 'apache'); ?>>
                                Apache
                            </label>
                        </fieldset>
                        <p class="description">
                            <strong>Nginx:</strong> Headers are sent via PHP on every WordPress request.<br>
                            <strong>Apache:</strong> Headers are written to <code>.htaccess</code> via <code>mod_headers</code> and apply to all requests including static files.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">Headers</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?= SWX_SH_OPTION ?>[enabled]" value="1"
                                <?php checked($opts['enabled']); ?>>
                            Enable security headers
                        </label>
                        <p class="description">Uncheck to disable all security headers (e.g. for debugging).</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row">CSP Mode</th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?= SWX_SH_OPTION ?>[report_only]" value="1"
                                <?php checked($opts['report_only']); ?>>
                            Report-Only mode
                        </label>
                        <p class="description">
                            Sends <code>Content-Security-Policy-Report-Only</code> instead of enforcing.
                            Check the browser console for violations without blocking anything.
                        </p>
                    </td>
                </tr>

            </table>

            <?php if (!$opts['enabled']): ?>
                <div class="notice notice-error inline">
                    <p><strong>Security headers are disabled.</strong></p>
                </div>
            <?php elseif ($opts['report_only']): ?>
                <div class="notice notice-warning inline">
                    <p><strong>Report-Only mode is active.</strong> CSP violations are logged to the browser console but not enforced.</p>
                </div>
            <?php else: ?>
                <div class="notice notice-success inline">
                    <p><strong>Security headers are active and enforcing</strong> via <?= $apache ? 'Apache (.htaccess)' : 'Nginx (PHP)' ?>.</p>
                </div>
            <?php endif; ?>

            <?php submit_button(); ?>
        </form>

        <hr>
        <h2>Active Headers</h2>
        <p>When enabled and enforcing, the following headers are sent on every page:</p>
        <table class="widefat striped" style="max-width:900px">
            <thead>
                <tr><th>Header</th><th>Value</th></tr>
            </thead>
            <tbody>
                <tr><td><code>X-Frame-Options</code></td><td><code>SAMEORIGIN</code></td></tr>
                <tr><td><code>X-Content-Type-Options</code></td><td><code>nosniff</code></td></tr>
                <tr><td><code>Strict-Transport-Security</code></td><td><code><?= esc_html(swx_sh_hsts_value()) ?></code> (HTTPS only)</td></tr>
                <tr><td><code>Referrer-Policy</code></td><td><code>strict-origin-when-cross-origin</code></td></tr>
                <tr><td><code>Permissions-Policy</code></td><td><code><?= esc_html(swx_sh_build_permissions()) ?></code></td></tr>
                <tr>
                    <td><code><?= $opts['report_only'] ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy' ?></code></td>
                    <td style="word-break:break-all;font-size:12px"><code><?= esc_html(swx_sh_build_csp()) ?></code></td>
                </tr>
            </tbody>
        </table>

        <?php if ($apache && $opts['enabled']): ?>
        <hr>
        <h2>.htaccess Block</h2>
        <p>The following was written to <code><?= esc_html($htaccess) ?></code>:</p>
        <pre style="background:#f6f7f7;padding:12px;max-width:900px;overflow-x:auto;font-size:12px"><?php
            foreach (swx_sh_build_htaccess_lines($opts) as $line) {
                echo esc_html($line) . "\n";
            }
        ?></pre>
        <?php endif; ?>

    </div>
    <?php
}
