<?php

/**
 * Developer: Andy Goldau
 * © 2026 FP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 *
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * FP-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by P.A.G.M. OU (FASTPANEL) or its affiliates.
 */

/**
 * FastPanel Registration Script - Configuration
 * -----------------------------------------------
 * Adjust these values to match your FastPanel server.
 */

// ── FastPanel Server ──────────────────────────────────────────────────────────
define('FP_HOST', 'https://your-server.example.com'); // IP or hostname WITHOUT trailing slash
define('FP_PORT', 8888);                               // Integer: default FastPanel port (8888)

// ── SSL Certificate Verification ─────────────────────────────────────────────
// Set to true in production (recommended).
// Set to false ONLY if your FastPanel server uses a self-signed certificate.
define('FP_SSL_VERIFY', true);

// ── API Token (for API Authentication) ───────────────────────────────────────
// Generate your API token in FastPanel:
//   1. Click your username in the top-right corner of the FastPanel interface.
//   2. Select "API tokens" → click "Add API Token".
//   3. Fill in the name, optionally restrict by IP and set an expiry date.
//   4. Click "Add" and SAVE the token immediately - you won't see it again!
//
// SECURITY BEST PRACTICE: Restrict the token to the IP of the server running this script.
// NOTE: API token management currently requires FastPanel on Ubuntu 20.04.
//
// IMPORTANT: Even with automated registration, implement a manual vetting process
// for new customers to prevent spam, fraud, or abuse of your hosting infrastructure.
define('FP_API_TOKEN', 'your-fastpanel-api-token');

// ── Default Role for New Users ────────────────────────────────────────────────
// 'USER' for regular users, 'RESELLER' for reseller accounts.
define('FP_DEFAULT_ROLE', 'USER');

// ── Resource Limits for New Accounts (optional) ───────────────────────────────
// Set to 0 to use the FastPanel server defaults (unlimited or configured default).
define('FP_MAX_SITES', 0);         // Maximum number of websites (0 = server default)
define('FP_DISK_QUOTA_MB', 0);     // Disk quota in megabytes (0 = server default)

// ── Queue Polling Settings ────────────────────────────────────────────────────
// FastPanel's API is asynchronous: account creation is queued and processed
// in the background. This script polls the queue until success or timeout.
define('FP_QUEUE_POLL_ATTEMPTS', 6);    // Number of polling attempts (default: 6)
define('FP_QUEUE_POLL_SLEEP', 4);       // Seconds between polling attempts (default: 4)

// ── Rate Limiting & Proxy Configuration ──────────────────────────────────────
// Set to true ONLY if your server is behind a trusted reverse proxy or Cloudflare.
define('TRUST_PROXY_HEADERS', false);

define('RATE_LIMIT_MAX', 5);   // Maximum registrations per window
define('RATE_LIMIT_WINDOW', 300);  // Time window in seconds (5 minutes)

// ── Password Policy ─────────────────────────────────────────────────────────
define('PASSWD_MIN_LENGTH', 8);
define('PASSWD_REQUIRE_COMPLEXITY', true);
define('PASSWD_SHOW_CHECKLIST', true);

// ── Site Title & Branding ───────────────────────────────────────────────────
define('SITE_TITLE', 'FASTPANEL - Registration');
define('PANEL_URL', FP_HOST . ':' . FP_PORT . '/');

// ── Card Heading & Subheading ────────────────────────────────────────────────
define('CARD_HEADING', 'FASTPANEL');
define('CARD_SUBHEADING', 'web control panel');

// ── Cookie Consent Banner ────────────────────────────────────────────────────
define('COOKIE_BANNER_ENABLED', true);
define('COOKIE_BANNER_TEXT', 'We use essential cookies for security (CSRF, session). By continuing, you agree to our cookie usage.');
define('COOKIE_BANNER_BTN', 'Accept & Continue');

// ── Accessibility Widget ─────────────────────────────────────────────────────
define('ACCESSIBILITY_WIDGET_ENABLED', true);

// ── CAPTCHA Configuration ────────────────────────────────────────────────────
// Choose ONE provider: 'none' | 'hcaptcha' | 'recaptcha' | 'altcha' | 'turnstile' | 'mtcaptcha'
define('CAPTCHA_PROVIDER', 'hcaptcha');

define('HCAPTCHA_SITE_KEY', 'your-hcaptcha-site-key');
define('HCAPTCHA_SECRET_KEY', 'your-hcaptcha-secret-key');

define('RECAPTCHA_SITE_KEY', 'your-recaptcha-site-key');
define('RECAPTCHA_SECRET_KEY', 'your-recaptcha-secret-key');

// ALTCHA - Generate secret: openssl rand -hex 32
define('ALTCHA_HMAC_KEY', 'CHANGE_THIS_TO_A_STRONG_RANDOM_SECRET');

define('TURNSTILE_SITE_KEY', 'your-turnstile-site-key');
define('TURNSTILE_SECRET_KEY', 'your-turnstile-secret-key');

define('MTCAPTCHA_SITE_KEY', 'your-mtcaptcha-sitekey');
define('MTCAPTCHA_PRIVATE_KEY', 'your-mtcaptcha-privatekey');

// ── Legal / Compliance (DSGVO / GDPR) ─────────────────────────────────────
define('TOS_URL', 'https://example.com/agb');
define('PRIVACY_URL', 'https://example.com/datenschutz');

// ── Font Provider (DSGVO / GDPR Compliance) ─────────────────────────────────
// Choose font provider: 'bunny' (Bunny Fonts - DSGVO compliant, default) | 'google' (Google Fonts) | 'none' (System Fonts)
define('FONT_PROVIDER', 'bunny');


// ── Support / Contact ────────────────────────────────────────────────────────
define('SUPPORT_EMAIL', 'support@example.com');
define('SUPPORT_URL', '');


// ── Abuse Protection (Disposable Email Blocker) ───────────────────────────
define('BLOCKED_EMAIL_DOMAINS', [
    '10minutemail.com',
    'trashmail.de',
    'trashmail.com',
    'mailinator.com',
    'yopmail.com',
    'guerrillamail.com',
    'temp-mail.org',
    'tempmail.com',
    'sharklasers.com',
    'dispostable.com',
    'maildrop.cc'
]);

// ── Admin Notifications (Email & Webhook) ─────────────────────────────────
define('ADMIN_EMAIL', '');
define('WEBHOOK_ENABLED', false);
define('WEBHOOK_URL', 'https://discord.com/api/webhooks/your-webhook-id/your-webhook-token');

// ── Maintenance Mode ──────────────────────────────────────────────────────
define('MAINTENANCE_MODE', false);

// ── Reserved Usernames ──────────────────────────────────────────────────────
define('RESERVED_USERNAMES', [
    'admin', 'administrator', 'root', 'support', 'billing',
    'webmaster', 'hostmaster', 'postmaster', 'sysadmin', 'info', 'test'
]);

// ── DNS MX Record Check ────────────────────────────────────────────────────
define('ENABLE_MX_CHECK', true);

// ── HaveIBeenPwned Password Check ─────────────────────────────────────────
define('ENABLE_HIBP_CHECK', true);
define('HIBP_BLOCK_ON_BREACH', false);

// ── Audit Log ──────────────────────────────────────────────────────────────────
define('AUDIT_LOG_ENABLED', true);
define('AUDIT_LOG_PATH', __DIR__ . '/logs/audit.log.php');
define('AUDIT_LOG_MAX_SIZE', 10 * 1024 * 1024); // 10 MB
// Generate salt: openssl rand -hex 16
define('LOG_IP_SALT', 'CHANGE_TO_RANDOM_SALT_FOR_GDPR');

// ── Invite Codes (Invite-Only Mode) ──────────────────────────────────────────
define('INVITE_ONLY_MODE', false);
define('INVITE_SINGLE_USE', true);
define('INVITE_CODES', [
    'WELCOME-2026',
    'BETA-ACCESS',
    'VIP-HOSTING',
]);
define('INVITE_CODES_FILE', __DIR__ . '/data/used_codes.php');

// ── Demo Mode ─────────────────────────────────────────────────────────────────
// Setup cronjob: */30 * * * * php /path/to/cron_cleanup.php >> /dev/null 2>&1
define('DEMO_MODE', false);
define('DEMO_LIFETIME_HOURS', 2);
define('DEMO_ACCOUNTS_FILE', __DIR__ . '/data/demo_accounts.json');
