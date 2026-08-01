<?php
/**
 * Developer: Andy Goldau
 * © 2026 FP-Register by PanelLayer, a brand of Subdomain LTD and managed on behalf of GoMaKe UG. All rights reserved.
 * DISCLAIMER: This software is provided "as is" without any warranty of any kind.
 * FP-Register is an independent software solution and is not affiliated with,
 * endorsed by, or sponsored by P.A.G.M. OU (FASTPANEL) or its affiliates.
 */

error_reporting(0);
ini_set('display_errors', '0');

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
  || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
  || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

session_start([
  'cookie_httponly' => true,
  'cookie_samesite' => 'Lax',
  'cookie_secure' => $isHttps,
]);
require_once __DIR__ . '/config.php';

// Security Headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header(
  "Content-Security-Policy: default-src 'self'; "
  . "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net "
  . "https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "frame-src 'self' https://hcaptcha.com https://*.hcaptcha.com https://www.google.com https://challenges.cloudflare.com https://service.mtcaptcha.com https://service2.mtcaptcha.com; "
  . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.bunny.net; "
  . "font-src 'self' https://fonts.gstatic.com https://fonts.bunny.net; "
  . "connect-src 'self' https://api.hcaptcha.com https://*.hcaptcha.com https://challenges.cloudflare.com https://www.google.com https://service.mtcaptcha.com https://service2.mtcaptcha.com https://api.pwnedpasswords.com; "
  . "img-src 'self' data: https://*.hcaptcha.com https://www.google.com https://www.gstatic.com https://service.mtcaptcha.com https://service2.mtcaptcha.com;"
);

// CSRF Token
if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

// Rate Limiting (Token Bucket)
if (defined('TRUST_PROXY_HEADERS') && TRUST_PROXY_HEADERS) {
  $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
} else {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}
$ip = explode(',', trim($ip))[0];

$rateLimitDir = __DIR__ . '/data/limits';
if (!is_dir($rateLimitDir))
  @mkdir($rateLimitDir, 0750, true);

$ipHash = hash('sha256', (defined('LOG_IP_SALT') ? LOG_IP_SALT : 'fallback') . $ip);
$limitFile = $rateLimitDir . '/limit_' . $ipHash . '.php';
$capacity = RATE_LIMIT_MAX;
$refillRate = $capacity / RATE_LIMIT_WINDOW;
$tokens = $capacity;
$lastUpdate = time();
$rateLimited = false;
$isPost = ($_SERVER['REQUEST_METHOD'] === 'POST');

$fp = @fopen($limitFile, 'c+');
if ($fp) {
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    if (strlen($raw) > 15) {
      $data = json_decode(substr($raw, 15), true);
      if (is_array($data)) {
        $tokens = $data['tokens'] ?? $capacity;
        $lastUpdate = $data['last_update'] ?? time();
      }
    }
    $now = time();
    $elapsed = $now - $lastUpdate;
    $tokens += $elapsed * $refillRate;
    if ($tokens > $capacity)
      $tokens = $capacity;
    if ($isPost) {
      if ($tokens >= 1) {
        $tokens -= 1;
        $rateLimited = false;
      } else {
        $rateLimited = true;
      }
    } else {
      $rateLimited = ($tokens < 1);
    }
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, "<?php exit; ?>\n" . json_encode(['tokens' => $tokens, 'last_update' => $now]));
    flock($fp, LOCK_UN);
  }
  fclose($fp);
}

// ── FastPanel Queue Poller ─────────────────────────────────────────────────
function fpPollQueue(string $queueId): array
{
  $url = rtrim(FP_HOST, '/') . ':' . FP_PORT . '/api/queue/' . rawurlencode($queueId) . '/event';
  $attempts = defined('FP_QUEUE_POLL_ATTEMPTS') ? (int) FP_QUEUE_POLL_ATTEMPTS : 6;
  $sleep = defined('FP_QUEUE_POLL_SLEEP') ? (int) FP_QUEUE_POLL_SLEEP : 4;

  for ($i = 0; $i < $attempts; $i++) {
    sleep($sleep);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_HTTPHEADER => ['Authorization: ' . FP_API_TOKEN, 'Accept: application/json'],
      CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY,
      CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0,
      CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_TIMEOUT => 15,
    ]);
    $resp = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$resp)
      continue;

    $json = json_decode((string) $resp, true);
    if (!is_array($json))
      continue;
    $status = strtoupper($json['status'] ?? $json['event_status'] ?? '');

    if ($status === 'SUCCESS') {
      return ['success' => true, 'message' => 'Account successfully created!'];
    }
    if (in_array($status, ['FAILED', 'FAILURE', 'ERROR'], true)) {
      $msg = $json['result']['error'] ?? $json['result']['message'] ?? $json['message'] ?? 'Account creation failed.';
      return ['success' => false, 'message' => htmlspecialchars((string) $msg)];
    }
    // STARTED / PENDING / SUSPEND -> keep polling
  }
  return [
    'success' => false,
    'message' => 'Account creation is taking longer than expected. Please check FastPanel directly or contact support.'
  ];
}

// ── FastPanel API: Create User ─────────────────────────────────────────────
function fpCreateUser(array $data): array
{
  $url = rtrim(FP_HOST, '/') . ':' . FP_PORT . '/api/users';
  $payload = ['login' => $data['username'], 'password' => $data['passwd'], 'email' => $data['email'], 'role' => defined('FP_DEFAULT_ROLE') ? FP_DEFAULT_ROLE : 'USER'];
  if (defined('FP_MAX_SITES') && FP_MAX_SITES > 0)
    $payload['max_sites'] = (int) FP_MAX_SITES;
  if (defined('FP_DISK_QUOTA_MB') && FP_DISK_QUOTA_MB > 0)
    $payload['quota'] = (int) FP_DISK_QUOTA_MB;

  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => json_encode($payload),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HEADER => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json', 'Authorization: ' . FP_API_TOKEN],
    CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY,
    CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 30,
  ]);
  $response = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  $errno = curl_errno($ch);
  $errorMsg = curl_error($ch);
  curl_close($ch);

  if ($errno)
    return ['success' => false, 'message' => 'Connection to FastPanel failed: ' . htmlspecialchars($errorMsg)];
  if ($httpCode === 401)
    return ['success' => false, 'message' => 'Authentication failed (401). Please check FP_API_TOKEN in config.php.'];
  if ($httpCode === 403)
    return ['success' => false, 'message' => 'Access forbidden (403). The API token lacks sufficient permissions.'];

  if ($httpCode === 422) {
    $body = substr((string) $response, $headerSize);
    $json = json_decode($body, true);
    $msg = $json['message'] ?? $json['detail'] ?? 'Validation error.';
    if (is_array($msg))
      $msg = implode('; ', array_column($msg, 'msg'));
    return ['success' => false, 'message' => htmlspecialchars((string) $msg)];
  }

  if ($httpCode === 202) {
    $headers = substr((string) $response, 0, $headerSize);
    if (preg_match('/Queue-Event-ID:\s*([^\r\n]+)/i', $headers, $m)) {
      $queueId = trim($m[1]);
      if ($queueId)
        return fpPollQueue($queueId);
    }
    return ['success' => true, 'message' => 'Account creation initiated. Please log in to FastPanel shortly.'];
  }

  if ($httpCode === 200 || $httpCode === 201) {
    $body = substr((string) $response, $headerSize);
    $json = json_decode($body, true);
    if (is_array($json)) {
      $status = strtoupper($json['status'] ?? '');
      if ($status === 'SUCCESS' || isset($json['id']) || isset($json['login']))
        return ['success' => true, 'message' => 'Account successfully created!'];
      $msg = $json['message'] ?? $json['detail'] ?? 'Unknown response.';
      return ['success' => false, 'message' => htmlspecialchars((string) $msg)];
    }
    return ['success' => true, 'message' => 'Account successfully created!'];
  }

  $body = substr((string) $response, $headerSize);
  $json = json_decode($body, true);
  $msg = $json['message'] ?? $json['detail'] ?? null;
  if ($msg)
    return ['success' => false, 'message' => htmlspecialchars((string) $msg)];
  $clean = trim(strip_tags($body));
  if (!empty($clean)) {
    $snippet = mb_strlen($clean) > 200 ? mb_substr($clean, 0, 200) . '...' : $clean;
    return ['success' => false, 'message' => 'Server error (HTTP ' . $httpCode . '): ' . htmlspecialchars($snippet)];
  }
  return ['success' => false, 'message' => 'Unknown error from FastPanel (HTTP ' . $httpCode . ').'];
}

// ── Audit Log ──────────────────────────────────────────────────────────────
function auditLog(string $username, string $email, string $result, string $reason): void
{
  if (!defined('AUDIT_LOG_ENABLED') || !AUDIT_LOG_ENABLED)
    return;
  $logPath = AUDIT_LOG_PATH;
  $logDir = dirname($logPath);
  if (!is_dir($logDir))
    @mkdir($logDir, 0750, true);
  if (file_exists($logPath) && filesize($logPath) > AUDIT_LOG_MAX_SIZE)
    @rename($logPath, $logPath . '.' . date('Ymd-His'));
  $rawIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  $anonIp = substr(hash('sha256', $rawIp . LOG_IP_SALT), 0, 16);
  $maskedEmail = '';
  if ($email && strpos($email, '@') !== false) {
    [$local, $dom] = explode('@', $email, 2);
    $maskedEmail = substr($local, 0, 1) . '***@' . $dom;
  }
  $entry = json_encode(['t' => date('c'), 'ip' => $anonIp, 'user' => $username, 'email' => $maskedEmail, 'result' => $result, 'reason' => $reason ?: null], JSON_UNESCAPED_UNICODE);
  $fp = @fopen($logPath, 'a');
  if ($fp) {
    flock($fp, LOCK_EX);
    if (filesize($logPath) === 0)
      fwrite($fp, "<?php exit; ?>\n");
    fwrite($fp, $entry . "\n");
    flock($fp, LOCK_UN);
    fclose($fp);
  }
}

// ── DNS MX Check ───────────────────────────────────────────────────────────
function checkEmailMx(string $domain): bool
{
  if (!defined('ENABLE_MX_CHECK') || !ENABLE_MX_CHECK)
    return true;
  if (!$domain)
    return false;
  $cacheKey = 'mx_' . md5($domain);
  if (isset($_SESSION[$cacheKey]) && (time() - $_SESSION[$cacheKey]['ts']) < 60)
    return $_SESSION[$cacheKey]['result'];
  set_error_handler(function () {}, E_WARNING);
  $records = dns_get_record($domain, DNS_MX | DNS_A);
  restore_error_handler();
  if ($records === false) {
    $_SESSION[$cacheKey] = ['result' => true, 'ts' => time()];
    return true;
  }
  $hasMx = !empty($records);
  $_SESSION[$cacheKey] = ['result' => $hasMx, 'ts' => time()];
  return $hasMx;
}

// ── Invite Code ────────────────────────────────────────────────────────────
function validateInviteCode(string $code): bool
{
  if (!defined('INVITE_ONLY_MODE') || !INVITE_ONLY_MODE)
    return true;
  $code = strtoupper(preg_replace('/[^A-Z0-9\-]/', '', strtoupper(trim($code))));
  if (!$code)
    return false;
  $isValid = false;
  foreach (INVITE_CODES as $validCode) {
    if (hash_equals(strtoupper(trim($validCode)), $code)) {
      $isValid = true;
      break;
    }
  }
  if (!$isValid)
    return false;
  if (!defined('INVITE_SINGLE_USE') || !INVITE_SINGLE_USE)
    return true;
  $file = INVITE_CODES_FILE;
  $dir = dirname($file);
  if (!is_dir($dir))
    @mkdir($dir, 0750, true);
  if (!file_exists($file))
    file_put_contents($file, "<?php exit; ?>\n" . json_encode(['used' => []]));
  $fp = @fopen($file, 'r+');
  if (!$fp)
    return false;
  $result = false;
  if (flock($fp, LOCK_EX)) {
    $raw = stream_get_contents($fp);
    $jsonStr = substr($raw, 15) ?: '{}';
    $data = json_decode($jsonStr, true) ?? ['used' => []];
    if (!in_array($code, (array) ($data['used'] ?? []), true)) {
      $data['used'][] = $code;
      rewind($fp);
      ftruncate($fp, 0);
      fwrite($fp, "<?php exit; ?>\n" . json_encode($data, JSON_PRETTY_PRINT));
      $result = true;
    }
    flock($fp, LOCK_UN);
  }
  fclose($fp);
  return $result;
}

// ── CAPTCHA ────────────────────────────────────────────────────────────────
function captchaCurl(string $url, array $data): array
{
  $ch = curl_init($url);
  curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($data), CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY, CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0, CURLOPT_TIMEOUT => 10]);
  $res = curl_exec($ch);
  curl_close($ch);
  return json_decode((string) $res, true) ?? [];
}

function verifyAltchaPayload(string $payload): bool
{
  if (!$payload)
    return false;
  $data = json_decode(base64_decode($payload), true);
  if (!is_array($data))
    return false;
  $alg = $data['algorithm'] ?? '';
  $challenge = $data['challenge'] ?? '';
  $salt = $data['salt'] ?? '';
  $number = (string) ($data['number'] ?? '');
  $signature = $data['signature'] ?? '';
  if ($alg !== 'SHA-256')
    return false;
  $query = parse_url($salt, PHP_URL_QUERY) ?? '';
  parse_str($query, $saltParams);
  if (isset($saltParams['expires']) && time() > (int) $saltParams['expires'])
    return false;
  if (hash('sha256', $salt . $number) !== $challenge)
    return false;
  return hash_equals(hash_hmac('sha256', $challenge, ALTCHA_HMAC_KEY), $signature);
}

function verifyCaptcha(): bool
{
  $provider = CAPTCHA_PROVIDER;
  if ($provider === 'none')
    return true;
  if ($provider === 'hcaptcha') {
    $token = $_POST['h-captcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://api.hcaptcha.com/siteverify', ['secret' => HCAPTCHA_SECRET_KEY, 'response' => $token, 'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '']);
    return ($r['success'] ?? false) === true;
  }
  if ($provider === 'recaptcha') {
    $token = $_POST['g-recaptcha-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://www.google.com/recaptcha/api/siteverify', ['secret' => RECAPTCHA_SECRET_KEY, 'response' => $token, 'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '']);
    return ($r['success'] ?? false) === true;
  }
  if ($provider === 'altcha')
    return verifyAltchaPayload($_POST['altcha'] ?? '');
  if ($provider === 'turnstile') {
    $token = $_POST['cf-turnstile-response'] ?? '';
    if (!$token)
      return false;
    $r = captchaCurl('https://challenges.cloudflare.com/turnstile/v0/siteverify', ['secret' => TURNSTILE_SECRET_KEY, 'response' => $token, 'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '']);
    return ($r['success'] ?? false) === true;
  }
  if ($provider === 'mtcaptcha') {
    $token = $_POST['mtcaptcha-verifiedtoken'] ?? '';
    if (!$token)
      return false;
    $url = 'https://service.mtcaptcha.com/mtcv1/api/checktoken?privatekey=' . urlencode(MTCAPTCHA_PRIVATE_KEY) . '&token=' . urlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY, CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0, CURLOPT_TIMEOUT => 10]);
    $res = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno || !$res)
      return false;
    $parsed = json_decode($res, true);
    return ($parsed['success'] ?? false) === true;
  }
  return false;
}

// ── Process Form ───────────────────────────────────────────────────────────
$result = null;
if ($rateLimited && $_SERVER['REQUEST_METHOD'] !== 'POST') {
  $result = ['success' => false, 'message' => 'Too many registration attempts. Please wait a few minutes before trying again.'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!empty($_POST['website_hp'])) {
    $result = ['success' => true, 'message' => 'Account successfully created!'];
  } elseif (!hash_equals($csrf, $_POST['csrf_token'] ?? '')) {
    $result = ['success' => false, 'message' => 'Invalid security token. Please refresh the page.'];
  } elseif ($rateLimited) {
    $result = ['success' => false, 'message' => 'Too many registrations. Please wait a few minutes.'];
  } elseif (CAPTCHA_PROVIDER !== 'none' && !verifyCaptcha()) {
    $result = ['success' => false, 'message' => 'CAPTCHA verification failed. Please try again.'];
  } else {
    $username = strtolower(trim($_POST['username'] ?? ''));
    $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
    $passwd = $_POST['passwd'] ?? '';
    $passwd2 = $_POST['passwd2'] ?? '';
    $emailDomain = $email ? substr(strrchr($email, "@"), 1) : '';

    if (MAINTENANCE_MODE) {
      $result = ['success' => false, 'message' => 'Registrations are currently paused.'];
      auditLog($username ?? '', $email ?: '', 'fail', 'maintenance_mode');
    } elseif ((!empty(TOS_URL) || !empty(PRIVACY_URL)) && empty($_POST['tos_agree'])) {
      $result = ['success' => false, 'message' => 'You must agree to the Terms of Service and Privacy Policy.'];
      auditLog($username ?? '', $email ?: '', 'fail', 'tos_not_agreed');
    } elseif (INVITE_ONLY_MODE && !validateInviteCode($_POST['invite_code'] ?? '')) {
      $result = ['success' => false, 'message' => 'invite_invalid'];
      auditLog($username ?? '', $email ?: '', 'fail', 'invite_invalid');
    } elseif (!preg_match('/^[a-z0-9]{4,16}$/', $username)) {
      $result = ['success' => false, 'message' => 'Username must be 4-16 characters long (a-z, 0-9 only).'];
      auditLog($username, $email ?: '', 'fail', 'username_invalid');
    } elseif (in_array(strtolower($username), RESERVED_USERNAMES)) {
      $result = ['success' => false, 'message' => 'This username is reserved and cannot be registered.'];
      auditLog($username, $email ?: '', 'fail', 'username_reserved');
    } elseif (!$email) {
      $result = ['success' => false, 'message' => 'Please enter a valid email address.'];
      auditLog($username, '', 'fail', 'email_invalid');
    } elseif ($emailDomain && in_array(strtolower($emailDomain), BLOCKED_EMAIL_DOMAINS)) {
      $result = ['success' => false, 'message' => 'This email provider is not allowed.'];
      auditLog($username, $email, 'fail', 'email_domain_blocked');
    } elseif ($emailDomain && !checkEmailMx($emailDomain)) {
      $result = ['success' => false, 'message' => 'email_mx_invalid'];
      auditLog($username, $email, 'fail', 'email_mx_no_records');
    } elseif (strlen($passwd) < PASSWD_MIN_LENGTH) {
      $result = ['success' => false, 'message' => 'Password must be at least ' . PASSWD_MIN_LENGTH . ' characters long.'];
      auditLog($username, $email, 'fail', 'password_too_short');
    } elseif (PASSWD_REQUIRE_COMPLEXITY && (!preg_match('/[A-Z]/', $passwd) || !preg_match('/[a-z]/', $passwd) || !preg_match('/[0-9]/', $passwd))) {
      $result = ['success' => false, 'message' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number.'];
      auditLog($username, $email, 'fail', 'password_complexity');
    } elseif ($passwd !== $passwd2) {
      $result = ['success' => false, 'message' => 'Passwords do not match.'];
      auditLog($username, $email, 'fail', 'password_mismatch');
    } else {
      @set_time_limit(120);
      if (session_status() === PHP_SESSION_ACTIVE)
        session_write_close();

      $result = fpCreateUser(['username' => $username, 'email' => $email, 'passwd' => $passwd, 'passwd2' => $passwd2]);
      auditLog($username, $email, $result['success'] ? 'success' : 'fail', $result['success'] ? '' : 'fp_api_error');

      if ($result['success']) {
        if (WEBHOOK_ENABLED && !empty(WEBHOOK_URL)) {
          $wh = json_encode(['content' => "🔔 **New Registration**\nUser: `{$username}`\nEmail: `{$email}`"]);
          $ch = curl_init(WEBHOOK_URL);
          curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
          curl_setopt($ch, CURLOPT_POST, 1);
          curl_setopt($ch, CURLOPT_POSTFIELDS, $wh);
          curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
          curl_setopt($ch, CURLOPT_TIMEOUT, 3);
          curl_exec($ch);
          curl_close($ch);
        }
        if (!empty(ADMIN_EMAIL)) {
          $subject = "New Registration: $username";
          $msg = "A new user has registered.\n\nUsername: $username\nEmail: $email\nDate: " . date('Y-m-d H:i:s') . "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
          $rawHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
          $host = preg_replace('/[^a-zA-Z0-9\.\-]/', '', $rawHost) ?: 'localhost';
          $headers = "From: no-reply@" . $host . "\r\nReply-To: " . filter_var($email, FILTER_SANITIZE_EMAIL) . "\r\nX-Mailer: PHP/" . phpversion();
          @mail(ADMIN_EMAIL, $subject, $msg, $headers);
        }
        if (defined('DEMO_MODE') && DEMO_MODE) {
          $demoFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');
          $demoDir = dirname($demoFile);
          if (!is_dir($demoDir))
            @mkdir($demoDir, 0750, true);
          $accounts = is_file($demoFile) ? (json_decode(file_get_contents($demoFile), true) ?: []) : [];
          $accounts[$username] = ['email' => $email, 'created_at' => time(), 'delete_after' => time() + (defined('DEMO_LIFETIME_HOURS') ? (int) DEMO_LIFETIME_HOURS : 2) * 3600];
          file_put_contents($demoFile, json_encode($accounts, JSON_PRETTY_PRINT), LOCK_EX);
        }
      }
    }
  }

  if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax', 'cookie_secure' => $isHttps]);
  }
  if ($result && $result['success']) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf_token'];
  } else {
    $csrf = $_SESSION['csrf_token'] ?? $csrf;
  }
}


?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title><?= SITE_TITLE ?></title>
  <meta name="description" content="Web Hosting Account Registration" />
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet" />
  <!-- Original Diamond Favicon with FP blue -->
  <link rel="icon" type="image/svg+xml"
    href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 42 42'%3E%3Crect width='42' height='42' rx='10' fill='%231089d0'/%3E%3Cpath d='M8 21L16 13L24 21L16 29L8 21Z' fill='%23ffffff'/%3E%3Cpath d='M18 21L26 13L34 21L26 29L18 21Z' fill='%23ffffff' opacity='.6'/%3E%3C/svg%3E" />
  <?php
  $fontProvider = defined('FONT_PROVIDER') ? FONT_PROVIDER : 'bunny';
  if ($fontProvider === 'bunny'): ?>
    <link rel="preconnect" href="https://fonts.bunny.net" />
    <link href="https://fonts.bunny.net/css?family=inter:300,400,500,600,700&amp;display=swap" rel="stylesheet" />
  <?php elseif ($fontProvider === 'google'): ?>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&amp;display=swap"
      rel="stylesheet" />
  <?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script><?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'recaptcha'): ?>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script><?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'altcha'): ?>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script><?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'turnstile'): ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><?php endif; ?>
  <?php if (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
    <script>var mtcaptchaConfig = { "sitekey": "<?= htmlspecialchars(MTCAPTCHA_SITE_KEY) ?>" }; (function () { var s = document.createElement('script'); s.async = true; s.src = 'https://service.mtcaptcha.com/mtcv1/client/mtcaptcha.min.js'; document.head.appendChild(s) })();</script>
  <?php endif; ?>
  <style>
    /* ── FastPanel-style: dark left panel + decorative right panel ── */
    :root {
      --bg: #0e0f15;
      --panel-bg: #0e0f15;
      --card: transparent;
      --card-b: transparent;
      --input-bg: transparent;
      --input-b: rgba(255, 255, 255, .2);
      --input-bh: #0a4b91;
      --text: #ffffff;
      --sub: #a0a0a0;
      --btn: #0a4b91;
      --btn-h: #083d7a;
      --btn-text: #fff;
      --err-bg: rgba(220, 53, 69, .1);
      --err-b: rgba(220, 53, 69, .35);
      --err-text: #ff6b7a;
      --ok-bg: rgba(10, 75, 145, .1);
      --ok-b: rgba(10, 75, 145, .35);
      --ok-text: #0a4b91;
      --time: rgba(255, 255, 255, .25);
      --icon-btn: transparent;
      --icon-bth: rgba(255, 255, 255, .05);
      --sb-track: rgba(0, 0, 0, .2);
      --sb-thumb: rgba(255, 255, 255, .18);
      --sb-thumb-h: rgba(255, 255, 255, .32);
      --accent: #0a4b91;
    }

    [data-theme="light"] {
      --bg: #f5f6f8;
      --panel-bg: #f5f6f8;
      --card: transparent;
      --card-b: transparent;
      --input-bg: #ffffff;
      --input-b: rgba(0, 0, 0, .15);
      --input-bh: #0a4b91;
      --text: #0e0f15;
      --sub: #666666;
      --btn: #0a4b91;
      --btn-h: #083d7a;
      --btn-text: #fff;
      --err-bg: rgba(220, 53, 69, .07);
      --err-b: rgba(220, 53, 69, .28);
      --err-text: #c0392b;
      --ok-bg: rgba(10, 75, 145, .08);
      --ok-b: rgba(10, 75, 145, .3);
      --ok-text: #0a4b91;
      --time: rgba(0, 0, 0, .4);
      --icon-btn: transparent;
      --icon-bth: rgba(0, 0, 0, .05);
      --sb-track: rgba(0, 0, 0, .05);
      --sb-thumb: rgba(0, 0, 0, .2);
      --sb-thumb-h: rgba(0, 0, 0, .35);
    }

    *,
    *::before,
    *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0
    }

    * {
      scrollbar-width: thin;
      scrollbar-color: var(--sb-thumb) var(--sb-track)
    }

    ::-webkit-scrollbar {
      width: 7px
    }

    ::-webkit-scrollbar-track {
      background: var(--sb-track)
    }

    ::-webkit-scrollbar-thumb {
      background: var(--sb-thumb);
      border-radius: 4px
    }

    ::-webkit-scrollbar-thumb:hover {
      background: var(--sb-thumb-h)
    }

    /* ── Split layout ── */
    html,
    body {
      height: 100%;
      margin: 0;
      padding: 0;
      overflow: hidden;
    }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--text);
      display: grid;
      /* 1:1 ratio for left form panel vs right decorative panel */
      grid-template-columns: 1fr 1fr;
      height: 100vh;
      transition: background .3s, color .3s;
    }

    @media(max-width:900px) {
      body {
        grid-template-columns: 1fr;
        overflow-y: auto;
      }

      .side-pattern {
        display: none !important;
      }
    }

    /* ── Left panel (form area) ── */
    .side-form {
      position: relative;
      background: var(--panel-bg);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 40px 48px;
      overflow-y: auto;
      z-index: 10;
      height: 100%;
    }

    /* ── Right decorative panel ── */
    .side-pattern {
      position: relative;
      background: #020f2e;
      overflow: hidden;
      display: flex;
      align-items: stretch;
    }

    .side-pattern img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      object-position: center;
      display: block;
      opacity: .92;
    }

    /* ── Preloader ── */
    #preloader {
      position: fixed;
      inset: 0;
      background: var(--panel-bg);
      z-index: 9999;
      display: grid;
      place-content: center;
      transition: opacity .45s ease, visibility .45s ease;
    }

    #preloader.hidden {
      opacity: 0;
      visibility: hidden;
    }

    #preloader-spinner {
      color: var(--btn);
      display: inline-block;
      position: relative;
      width: 64px;
      height: 64px;
    }

    #preloader-spinner div {
      box-sizing: border-box;
      display: block;
      position: absolute;
      width: 64px;
      height: 64px;
      border: 5px solid currentColor;
      border-radius: 50%;
      animation: lds-ring 1.1s cubic-bezier(.5, 0, .5, 1) infinite;
      border-color: currentColor transparent transparent transparent;
    }

    #preloader-spinner div:nth-child(1) {
      animation-delay: -.45s
    }

    #preloader-spinner div:nth-child(2) {
      animation-delay: -.3s
    }

    #preloader-spinner div:nth-child(3) {
      animation-delay: -.15s
    }

    @keyframes lds-ring {
      0% {
        transform: rotate(0deg)
      }

      100% {
        transform: rotate(360deg)
      }
    }

    /* ── Top controls (fixed to left panel) ── */
    .top-controls {
      position: fixed;
      top: 20px;
      left: 20px;
      display: flex;
      gap: 8px;
      align-items: center;
      z-index: 200;
    }

    .icon-btn {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      background: var(--icon-btn);
      border: none;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background .2s;
      color: var(--text);
    }

    .icon-btn:hover {
      background: var(--icon-bth)
    }

    .icon-btn svg {
      width: 18px;
      height: 18px
    }

    .lang-dropdown-wrap {
      position: relative
    }

    .lang-btn {
      display: flex;
      align-items: center;
      gap: 6px;
      background: transparent;
      border: none;
      padding: 5px 0;
      color: var(--text);
      font-family: inherit;
      font-size: .85rem;
      font-weight: 400;
      cursor: pointer;
      transition: color .2s;
    }

    .lang-btn:hover {
      color: var(--btn)
    }

    .lang-btn svg {
      width: 14px;
      height: 14px;
      opacity: .7
    }

    .flag-icon {
      width: 20px;
      height: 20px;
      min-width: 20px;
      min-height: 20px;
      border-radius: 50%;
      overflow: hidden;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .flag-icon img,
    .lang-item img {
      width: 20px;
      height: 20px;
      min-width: 20px;
      min-height: 20px;
      border-radius: 50%;
      object-fit: cover;
      display: block;
      flex-shrink: 0;
    }

    .lang-dropdown {
      position: absolute;
      bottom: calc(100% + 8px);
      right: 0;
      background: var(--panel-bg);
      border: 1px solid var(--input-b);
      border-radius: 10px;
      padding: 5px;
      width: 140px;
      max-height: 240px;
      overflow-y: auto;
      box-shadow: 0 16px 40px rgba(0, 0, 0, .45);
      display: none;
      z-index: 300;
    }

    .lang-dropdown.show {
      display: block
    }

    .lang-item {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      padding: 8px 10px;
      border: none;
      background: transparent;
      color: var(--text);
      font-family: inherit;
      font-size: .85rem;
      border-radius: 6px;
      cursor: pointer;
      text-align: left;
      transition: background .15s;
    }

    .lang-item:hover {
      background: var(--icon-bth)
    }

    .lang-item.active {
      color: var(--btn);
      font-weight: 500
    }

    /* ── Card / form wrapper ── */
    .card {
      width: 100%;
      max-width: 380px;
    }

    /* ── Logo ── */
    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 40px;
      justify-content: center;
    }

    .logo-icon {
      width: 46px;
      height: 46px;
      flex-shrink: 0;
    }

    .logo-text h1 {
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -.025em;
      color: var(--text);
      font-style: italic;
    }

    .logo-text p {
      font-size: .78rem;
      color: var(--sub);
      margin-top: 2px;
      font-weight: 400;
    }

    /* ── Alerts ── */
    .alert {
      border-radius: 8px;
      padding: 11px 14px;
      font-size: .84rem;
      margin-bottom: 18px;
      border: 1px solid;
      line-height: 1.5;
    }

    .alert-error {
      background: var(--err-bg);
      border-color: var(--err-b);
      color: var(--err-text);
    }

    .alert-success {
      background: var(--ok-bg);
      border-color: var(--ok-b);
      color: var(--ok-text);
    }

    .alert a {
      color: inherit;
      font-weight: 600;
    }

    /* ── Fields ── */
    .field {
      margin-bottom: 20px;
    }

    label {
      display: block;
      font-size: .78rem;
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--text);
    }

    label::after {
      content: ' *';
      color: #e74c3c;
    }

    .input-wrap {
      position: relative;
    }

    input[type=text],
    input[type=email],
    input[type=password] {
      width: 100%;
      background: var(--input-bg);
      border: 1px solid var(--input-b);
      border-radius: 8px;
      color: var(--text);
      font-family: inherit;
      font-size: .9rem;
      padding: 11px 14px;
      outline: none;
      transition: border-color .2s, box-shadow .2s;
    }

    input:focus {
      border-color: var(--input-bh);
      box-shadow: 0 0 0 1px var(--input-bh);
    }

    input::placeholder {
      color: var(--sub);
      opacity: .4;
    }

    .eye-btn {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      cursor: pointer;
      color: var(--sub);
      display: flex;
      padding: 4px;
      transition: color .2s;
    }

    .eye-btn:hover {
      color: var(--text)
    }

    .pw-field {
      padding-right: 38px !important;
    }

    .copy-pw-btn {
      background: none;
      border: 1px solid var(--input-b);
      border-radius: 5px;
      cursor: pointer;
      color: var(--sub);
      font-size: .76rem;
      padding: 3px 9px;
      display: flex;
      align-items: center;
      gap: 4px;
      transition: all .2s;
      white-space: nowrap;
    }

    .copy-pw-btn:hover {
      color: var(--text);
      border-color: var(--btn)
    }

    .copy-pw-btn.copied {
      color: var(--btn);
      border-color: var(--btn);
    }

    .field-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    /* ── Button ── */
    .btn {
      width: 100%;
      padding: 12px;
      background: var(--btn);
      color: var(--btn-text);
      border: none;
      border-radius: 50px;
      font-family: inherit;
      font-size: .92rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: background .18s, transform .1s;
      margin-top: 24px;
    }

    .btn:hover {
      background: var(--btn-h);
    }

    .btn:active {
      transform: scale(.98);
    }

    .btn:disabled {
      opacity: .55;
      cursor: not-allowed;
      box-shadow: none;
    }

    .spinner {
      width: 17px;
      height: 17px;
      border: 2px solid rgba(255, 255, 255, .35);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin .7s linear infinite;
      display: none;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg)
      }
    }

    /* ── Password meter ── */
    .pw-meter {
      margin-top: 8px;
    }

    .pw-meter-bar {
      height: 3px;
      background: var(--input-bg);
      border-radius: 2px;
      overflow: hidden;
      border: 1px solid var(--input-b);
    }

    .pw-meter-fill {
      height: 100%;
      width: 0%;
      transition: width .3s ease, background-color .3s ease;
    }

    .pw-meter-text {
      font-size: .73rem;
      margin-top: 4px;
      color: var(--sub);
      display: flex;
      justify-content: space-between;
    }

    .pw-checklist {
      list-style: none;
      margin-top: 8px;
      padding: 0;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 5px 10px;
    }

    .pw-check-item {
      display: flex;
      align-items: center;
      gap: 4px;
      font-size: .72rem;
      color: var(--sub);
      transition: color .2s;
    }

    .pw-check-item .check-icon {
      width: 14px;
      height: 14px;
      border-radius: 50%;
      border: 1.5px solid var(--sub);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      transition: background .2s, border-color .2s;
      font-size: .6rem;
    }

    .pw-check-item.ok {
      color: var(--ok-text);
    }

    .pw-check-item.ok .check-icon {
      background: var(--ok-text);
      border-color: var(--ok-text);
      color: #fff;
    }

    /* ── HIBP ── */
    .hibp-status {
      font-size: .76rem;
      margin-top: 7px;
      padding: 5px 9px;
      border-radius: 5px;
      display: none;
    }

    .hibp-status.checking {
      display: block;
      color: var(--sub);
    }

    .hibp-status.warning {
      display: block;
      color: var(--err-text);
      background: var(--err-bg);
      border: 1px solid var(--err-b);
    }

    .hibp-status.ok {
      display: block;
      color: var(--ok-text);
      background: var(--ok-bg);
      border: 1px solid var(--ok-b);
    }

    /* ── FP Notice ── */
    .fp-notice {
      background: rgba(18, 92, 161, .07);
      border: 1px solid rgba(18, 92, 161, .2);
      border-radius: 7px;
      padding: 9px 12px;
      font-size: .8rem;
      color: var(--sub);
      line-height: 1.5;
      margin-bottom: 16px;
    }

    .fp-notice strong {
      color: var(--ok-text);
    }

    /* ── Help FAB ── */
    .help-fab-wrap {
      position: fixed;
      bottom: 18px;
      left: 16px;
      z-index: 100;
    }

    .help-fab {
      display: flex;
      align-items: center;
      gap: 7px;
      background: var(--icon-btn);
      border: 1px solid var(--card-b);
      border-radius: 18px;
      padding: 7px 14px;
      color: var(--text);
      font-family: inherit;
      font-size: .82rem;
      font-weight: 500;
      cursor: pointer;
      transition: background .2s;
    }

    .help-fab:hover {
      background: var(--icon-bth);
    }

    .help-fab svg {
      color: var(--btn);
    }

    .help-menu {
      position: absolute;
      bottom: calc(100% + 8px);
      left: 0;
      background: var(--panel-bg);
      border: 1px solid var(--input-b);
      border-radius: 10px;
      padding: 5px;
      width: 175px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, .4);
      display: none;
      flex-direction: column;
      z-index: 200;
    }

    .help-menu.show {
      display: flex;
      animation: fadeIn .2s ease-out;
    }

    .help-menu a {
      padding: 7px 11px;
      color: var(--text);
      text-decoration: none;
      font-size: .83rem;
      border-radius: 5px;
      transition: background .15s;
    }

    .help-menu a:hover {
      background: var(--icon-bth);
    }

    /* ── Login link & time ── */
    .bottom-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 24px;
    }

    .bottom-footer a {
      color: var(--btn);
      text-decoration: none;
      font-weight: 500;
      font-size: .85rem;
      transition: color .2s;
    }

    .bottom-footer a:hover {
      color: var(--btn-h);
    }


    /* ── ALTCHA ── */
    altcha-widget {
      --altcha-color-border: var(--input-b);
      --altcha-color-border-focus: var(--input-bh);
      --altcha-color-background: var(--input-bg);
      --altcha-color-text: var(--text);
      --altcha-color-text-secondary: var(--sub);
      --altcha-border-radius: 8px;
      width: 100%;
      margin-top: 16px;
      display: block;
    }

    /* ── Cookie banner & Accessibility ── */
    #cookieBanner {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 9998;
      background: rgba(17, 18, 22, .96);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-top: 1px solid rgba(255, 255, 255, .1);
      padding: 14px 22px;
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      justify-content: space-between;
      transform: translateY(100%);
      transition: transform .4s cubic-bezier(.16, 1, .3, 1);
    }

    #cookieBanner.visible {
      transform: translateY(0);
    }

    [data-theme="light"] #cookieBanner {
      background: rgba(245, 246, 248, .96);
    }

    #cookieBanner p {
      font-size: .82rem;
      color: var(--sub);
      line-height: 1.5;
      margin: 0;
      flex: 1;
      min-width: 180px;
    }

    #cookieAcceptBtn {
      background: var(--btn);
      color: #fff;
      border: none;
      border-radius: 50px;
      padding: 8px 20px;
      font-family: inherit;
      font-size: .84rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .2s;
      white-space: nowrap;
      flex-shrink: 0;
    }

    #cookieAcceptBtn:hover {
      background: var(--btn-h);
    }

    #a11yWidget {
      position: fixed;
      bottom: 18px;
      right: 18px;
      z-index: 500;
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 7px;
    }

    #a11yToggleBtn {
      width: 38px;
      height: 38px;
      border-radius: 50%;
      background: var(--btn);
      border: none;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: background .2s, transform .2s;
    }

    #a11yToggleBtn:hover {
      background: var(--btn-h);
      transform: scale(1.08);
    }

    #a11yToggleBtn svg {
      width: 19px;
      height: 19px;
    }

    #a11yPanel {
      background: var(--panel-bg);
      border: 1px solid var(--input-b);
      border-radius: 12px;
      padding: 13px 15px;
      width: 200px;
      box-shadow: 0 14px 36px rgba(0, 0, 0, .4);
      display: none;
      flex-direction: column;
      gap: 9px;
      animation: fadeIn .2s ease-out;
    }

    #a11yPanel.open {
      display: flex;
    }

    #a11yPanel h4 {
      font-size: .75rem;
      font-weight: 600;
      color: var(--sub);
      text-transform: uppercase;
      letter-spacing: .1em;
      margin: 0 0 3px;
      border-bottom: 1px solid var(--input-b);
      padding-bottom: 7px;
    }

    .a11y-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 7px;
    }

    .a11y-label {
      font-size: .8rem;
      color: var(--text);
    }

    .a11y-controls {
      display: flex;
      align-items: center;
      gap: 5px;
    }

    .a11y-btn {
      width: 26px;
      height: 26px;
      border-radius: 5px;
      background: var(--icon-bth);
      border: none;
      color: var(--text);
      font-size: .85rem;
      font-family: inherit;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: background .15s;
    }

    .a11y-btn:hover {
      background: var(--btn);
      color: #fff;
    }

    .a11y-toggle-switch {
      position: relative;
      width: 34px;
      height: 18px;
      cursor: pointer;
    }

    .a11y-toggle-switch input {
      opacity: 0;
      width: 0;
      height: 0;
      position: absolute;
    }

    .a11y-slider {
      position: absolute;
      inset: 0;
      background: var(--icon-bth);
      border-radius: 9px;
      transition: background .2s;
    }

    .a11y-slider::before {
      content: '';
      position: absolute;
      width: 12px;
      height: 12px;
      left: 3px;
      top: 3px;
      background: var(--sub);
      border-radius: 50%;
      transition: transform .2s, background .2s;
    }

    .a11y-toggle-switch input:checked+.a11y-slider {
      background: var(--btn);
    }

    .a11y-toggle-switch input:checked+.a11y-slider::before {
      transform: translateX(16px);
      background: #fff;
    }

    #a11yFontSize {
      font-size: .75rem;
      color: var(--sub);
      min-width: 20px;
      text-align: center;
    }

    /* ── RTL (Right-to-Left) Support ── */
    [dir="rtl"] {
      text-align: right;
    }

    [dir="rtl"] .top-controls {
      left: auto;
      right: 20px;
    }

    [dir="rtl"] .eye-btn {
      right: auto;
      left: 10px;
    }

    [dir="rtl"] .pw-field {
      padding-right: 14px !important;
      padding-left: 38px !important;
    }

    [dir="rtl"] .help-fab-wrap {
      left: auto;
      right: 16px;
    }

    [dir="rtl"] .help-menu {
      left: auto;
      right: 0;
    }

    [dir="rtl"] #a11yWidget {
      right: auto;
      left: 18px;
      align-items: flex-start;
    }

    [dir="rtl"] .lang-dropdown {
      right: auto;
      left: 0;
    }

    [dir="rtl"] .lang-item {
      text-align: right;
    }

    [dir="rtl"] .a11y-slider::before {
      left: auto;
      right: 3px;
    }

    [dir="rtl"] .a11y-toggle-switch input:checked+.a11y-slider::before {
      transform: translateX(-16px);
    }

    [dir="rtl"] .copy-pw-btn {
      flex-direction: row-reverse;
    }

    [dir="rtl"] .pw-meter-text {
      flex-direction: row-reverse;
    }

    [dir="rtl"] .bottom-footer {
      flex-direction: row-reverse;
    }

    [dir="rtl"] label::after {
      content: ' *';
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: translateY(5px)
      }

      to {
        opacity: 1;
        transform: translateY(0)
      }
    }
  </style>
</head>

<body>
  <div id="preloader">
    <div id="preloader-spinner">
      <div></div>
      <div></div>
      <div></div>
    </div>
  </div>

  <!-- ═══ Left: Form panel ═══ -->
  <div class="side-form" id="sideForm">
    <!-- Top controls inside left panel -->
    <div class="top-controls" role="toolbar" aria-label="Settings">
      <button class="icon-btn" id="themeToggle" aria-label="Toggle theme">
        <svg id="iconSun" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
          stroke-width="2" style="display:none">
          <circle cx="12" cy="12" r="4" />
          <path
            d="M12 2v2m0 16v2M4.22 4.22l1.42 1.42m12.72 12.72 1.42 1.42M2 12h2m16 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
        </svg>
        <svg id="iconMoon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"
          stroke-width="2">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      </button>
    </div>

    <div class="card">
      <!-- Logo -->
      <div class="logo">
        <svg class="logo-icon" viewBox="0 0 42 42" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="42" height="42" rx="10" fill="#1089d0" opacity=".15" />
          <path d="M8 21L16 13L24 21L16 29L8 21Z" fill="#1089d0" />
          <path d="M18 21L26 13L34 21L26 29L18 21Z" fill="#1089d0" opacity=".5" />
        </svg>
        <div class="logo-text">
          <h1><?= htmlspecialchars(defined('CARD_HEADING') ? CARD_HEADING : 'FASTPANEL') ?></h1>
          <p data-i18n="subtitle"><?= htmlspecialchars(defined('CARD_SUBHEADING') ? CARD_SUBHEADING : 'web control panel') ?></p>
        </div>
      </div>

      <?php if (MAINTENANCE_MODE): ?>
        <div style="text-align:center;padding:30px 10px 10px;">
          <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="var(--sub)" stroke-width="1.5"
            stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:18px;display:inline-block;">
            <path
              d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z">
            </path>
          </svg>
          <h2 style="margin-bottom:10px;font-weight:700;font-size:1.4rem;color:var(--text);"
            data-i18n="maintenance_heading">Maintenance Mode</h2>
          <p style="color:var(--sub);font-size:.92rem;line-height:1.5;" data-i18n="maintenance_text">New registrations are
            currently paused. Please check back later.</p>
        </div>
      <?php elseif ($result && $result['success']): ?>
        <div style="text-align:center;padding:28px 10px 8px;animation:fadeIn .4s ease-out;">
          <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#1089d0" stroke-width="1.5"
            stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:18px;display:inline-block;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
            <polyline points="22 4 12 14.01 9 11.01"></polyline>
          </svg>
          <h2 style="margin-bottom:10px;font-weight:700;font-size:1.5rem;color:var(--text);" data-i18n="success_heading">
            Account Created!</h2>
          <p style="color:var(--sub);margin-bottom:14px;font-size:.92rem;line-height:1.5;">
            <?= htmlspecialchars($result['message']) ?></p>
          <div
            style="background:rgba(16,137,208,.08);border:1px solid rgba(16,137,208,.25);border-radius:7px;padding:10px;margin-bottom:<?= (defined('DEMO_MODE') && DEMO_MODE) ? '13' : '22' ?>px;">
            <p style="color:var(--ok-text);font-size:.83rem;margin:0;line-height:1.4;" data-i18n="setup_2fa">We recommend
              enabling Two-Factor Authentication (2FA) in the panel.</p>
          </div>
          <?php if (defined('DEMO_MODE') && DEMO_MODE): ?>
            <p style="background:rgba(255,108,47,.1);border:1px solid rgba(255,108,47,.35);border-radius:8px;padding:11px 14px;margin-bottom:22px;font-size:.88rem;line-height:1.5;color:var(--text);"
              data-i18n-demo-hours="<?= (int) (defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?>"
              data-i18n="demo_notice">
              &#x23F1; This is a demo account and will be automatically deleted after
              <?= (int) (defined('DEMO_LIFETIME_HOURS') ? DEMO_LIFETIME_HOURS : 2) ?> hour(s).
            </p>
          <?php endif; ?>
          <a href="<?= htmlspecialchars(PANEL_URL) ?>" class="btn"
            style="text-decoration:none;display:inline-flex;width:auto;padding:0 28px;" data-i18n="to_panel">To Panel</a>
        </div>
      <?php else: ?>
        <?php if ($result && !$result['success']): ?>
          <div class="alert alert-error"><?= htmlspecialchars($result['message']) ?></div>
        <?php endif; ?>
        <form method="POST" action="" id="regForm" novalidate autocomplete="off">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>" />
          <input type="text" name="website_hp" style="display:none" tabindex="-1" autocomplete="off">
          <div class="field">
            <label for="username" data-i18n="username">Username</label>
            <input type="text" id="username" name="username" data-i18n-ph="username_ph" placeholder="4-16 chars, a-z 0-9"
              value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" maxlength="16" autocomplete="username" required>
          </div>
          <div class="field">
            <label for="email" data-i18n="email">Email Address</label>
            <input type="email" id="email" name="email" data-i18n-ph="email_ph" placeholder="user@example.com"
              value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" autocomplete="email" required>
            <div id="emailSuggestion" style="display:none;font-size:.82rem;margin-top:5px;color:var(--sub);"><span
                data-i18n="did_you_mean">Did you mean</span> <a href="#" id="emailSuggestionLink"
                style="color:var(--btn);text-decoration:none;font-weight:500;"></a>?</div>
          </div>
          <div class="fp-notice"><strong>&#x2139;&#xFE0F;</strong> <span data-i18n="domain_notice">Add your domain in the
              control panel after registering.</span></div>
          <div class="field-row">
            <div class="field" style="margin-bottom:0">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">
                <label for="passwd" data-i18n="password" style="margin-bottom:0;">Password</label>
                <button type="button" id="generatePwBtn"
                  style="background:none;border:none;cursor:pointer;color:var(--btn);font-size:.73rem;display:flex;align-items:center;gap:3px;padding:0;">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"
                    stroke-linecap="round" stroke-linejoin="round">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                  </svg>
                  <span data-i18n="generate">Generate</span>
                </button>
              </div>
              <div class="input-wrap">
                <input type="password" id="passwd" name="passwd" class="pw-field" data-i18n-ph="password_ph"
                  placeholder="Min. <?= PASSWD_MIN_LENGTH ?> chars" autocomplete="new-password" required>
                <button type="button" class="eye-btn" data-target="passwd" aria-label="Show password">
                  <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                  <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                    <path
                      d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                </button>
              </div>
            </div>
            <div class="field" style="margin-bottom:0">
              <label for="passwd2" data-i18n="confirm">Confirm</label>
              <div class="input-wrap">
                <input type="password" id="passwd2" name="passwd2" class="pw-field" data-i18n-ph="confirm_ph"
                  placeholder="Repeat" autocomplete="new-password" required>
                <button type="button" class="eye-btn" data-target="passwd2" aria-label="Show password">
                  <svg class="show-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                  <svg class="hide-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="none"
                    viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="display:none">
                    <path
                      d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                    <line x1="1" y1="1" x2="23" y2="23" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
          <div class="pw-meter" id="pwMeter">
            <div class="pw-meter-bar">
              <div class="pw-meter-fill" id="pwMeterFill"></div>
            </div>
            <div class="pw-meter-text">
              <span id="pwHint" data-i18n="pw_hint">A-Z, a-z, 0-9</span>
              <div style="display:flex;align-items:center;gap:9px;">
                <span id="pwMeterText"></span>
                <button type="button" id="copyPwBtn" class="copy-pw-btn" style="display:none;" title="Copy password">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                    stroke-linecap="round" stroke-linejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  <span id="copyPwLabel" data-i18n="copy_pw">Copy</span>
                </button>
              </div>
            </div>
          </div>
          <?php if (defined('PASSWD_SHOW_CHECKLIST') && PASSWD_SHOW_CHECKLIST): ?>
            <ul class="pw-checklist" id="pwChecklist" data-min="<?= PASSWD_MIN_LENGTH ?>"
              data-complexity="<?= PASSWD_REQUIRE_COMPLEXITY ? '1' : '0' ?>">
              <li class="pw-check-item" id="chk-length"><span class="check-icon">&#x2713;</span><span
                  data-i18n-min="pw_req_length">At least <?= PASSWD_MIN_LENGTH ?> characters</span></li>
              <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
                <li class="pw-check-item" id="chk-upper"><span class="check-icon">&#x2713;</span><span
                    data-i18n="pw_req_upper">One uppercase (A-Z)</span></li>
                <li class="pw-check-item" id="chk-lower"><span class="check-icon">&#x2713;</span><span
                    data-i18n="pw_req_lower">One lowercase (a-z)</span></li>
                <li class="pw-check-item" id="chk-number"><span class="check-icon">&#x2713;</span><span
                    data-i18n="pw_req_number">One number (0-9)</span></li>
              <?php endif; ?>
            </ul>
          <?php endif; ?>
          <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
            <div class="hibp-status" id="hibpStatus"></div><?php endif; ?>
          <?php if (defined('INVITE_ONLY_MODE') && INVITE_ONLY_MODE): ?>
            <div class="field"><label for="invite_code" data-i18n="invite_code">Invitation Code</label><input type="text"
                id="invite_code" name="invite_code" data-i18n-ph="invite_code_ph" placeholder="Enter your invite code"
                maxlength="32" autocomplete="off" spellcheck="false" style="text-transform:uppercase;letter-spacing:.05em;">
            </div>
          <?php endif; ?>
          <?php if (!empty(TOS_URL) || !empty(PRIVACY_URL)): ?>
            <div class="field" style="margin-top:13px;display:flex;align-items:flex-start;gap:8px;">
              <input type="checkbox" id="tos_agree" name="tos_agree" value="1" required
                style="margin-top:3px;cursor:pointer;width:auto;accent-color:var(--btn);">
              <label for="tos_agree"
                style="font-size:.82rem;color:var(--sub);line-height:1.4;font-weight:normal;cursor:pointer;">
                <span data-i18n="tos_prefix">I agree to the</span>
                <?php if (!empty(TOS_URL)): ?><a href="<?= htmlspecialchars(TOS_URL) ?>" target="_blank"
                    data-i18n="tos_link" style="color:var(--btn);">Terms of Service</a><?php endif; ?>
                <?php if (!empty(TOS_URL) && !empty(PRIVACY_URL)): ?><span data-i18n="tos_and">and</span><?php endif; ?>
                <?php if (!empty(PRIVACY_URL)): ?><a href="<?= htmlspecialchars(PRIVACY_URL) ?>" target="_blank"
                    data-i18n="privacy_link" style="color:var(--btn);">Privacy Policy</a><?php endif; ?>
              </label>
            </div>
          <?php endif; ?>
          <div class="captcha-wrapper" style="margin-top:16px;display:flex;justify-content:center;width:100%;">
            <?php if (CAPTCHA_PROVIDER === 'hcaptcha'): ?>
              <div class="h-captcha" data-sitekey="<?= htmlspecialchars(HCAPTCHA_SITE_KEY) ?>"></div><?php endif; ?>
            <?php if (CAPTCHA_PROVIDER === 'recaptcha'): ?>
              <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars(RECAPTCHA_SITE_KEY) ?>"></div><?php endif; ?>
            <?php if (CAPTCHA_PROVIDER === 'altcha'): ?><altcha-widget
                challengeurl="altcha-challenge.php"></altcha-widget><?php endif; ?>
            <?php if (CAPTCHA_PROVIDER === 'turnstile'): ?>
              <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>"></div><?php endif; ?>
            <?php if (CAPTCHA_PROVIDER === 'mtcaptcha'): ?>
              <div class="mtcaptcha"></div><?php endif; ?>
          </div>
          <button type="submit" class="btn" id="submitBtn" <?= $rateLimited ? 'disabled' : '' ?>>
            <div class="spinner" id="spinner"></div><span id="submitLabel" data-i18n="register">Register</span>
          </button>
        </form>

        <div class="bottom-footer">
          <a href="<?= htmlspecialchars(PANEL_URL) ?>" target="_blank" data-i18n="forgot_password">Forgot Password?</a>
          <div class="lang-dropdown-wrap" id="langWrap">
            <button type="button" class="lang-btn" id="langBtn" aria-label="Select language" aria-expanded="false">
              <span class="flag-icon" id="currentFlag"><img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0wIDM0NSAyNTYuNy0yNS41TDUxMiAzNDV2MTY3SDB6Ii8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0ibTAgMTY3IDI1NS0yMyAyNTcgMjN2MTc4SDB6Ii8+PHBhdGggZmlsbD0iIzMzMyIgZD0iTTAgMGg1MTJ2MTY3SDB6Ii8+PC9nPjwvc3ZnPg==" width="20" height="20" alt="de" style="border-radius:50%;display:block;object-fit:cover;"></span>
              <span id="currentLangLabel">Deutsch</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"
                stroke-linejoin="round">
                <path d="M6 9l6 6 6-6" />
              </svg>
            </button>
            <div class="lang-dropdown" id="langDropdown" role="menu"></div>
          </div>
        </div>
      <?php endif; ?>
    </div><!-- /.card -->
  </div><!-- /.side-form -->

  <!-- ═══ Right: Decorative pattern panel ═══ -->
  <div class="side-pattern" aria-hidden="true">
    <img src="muster-fp.svg" alt="" draggable="false" />
  </div>



  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
    <div id="cookieBanner" role="dialog" aria-label="Cookie consent" data-i18n-attr="aria-label:cookie_banner_label"
      aria-live="polite">
      <p id="cookieBannerText" data-i18n="cookie_banner_text"><?= htmlspecialchars(COOKIE_BANNER_TEXT) ?></p>
      <button id="cookieAcceptBtn" type="button"
        data-i18n="cookie_banner_btn"><?= htmlspecialchars(COOKIE_BANNER_BTN) ?></button>
    </div>
  <?php endif; ?>

  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
    <div id="a11yWidget" role="complementary" aria-label="Accessibility tools"
      data-i18n-attr="aria-label:a11y_widget_label">
      <div id="a11yPanel" role="region" aria-label="Accessibility options" data-i18n-attr="aria-label:a11y_panel_label">
        <h4 data-i18n="a11y_title">Accessibility</h4>
        <div class="a11y-row"><span class="a11y-label" data-i18n="a11y_font_size">Font Size</span>
          <div class="a11y-controls"><button class="a11y-btn" id="a11yFontDec" aria-label="Decrease font size"
              data-i18n-attr="aria-label:a11y_font_dec">A&#x2212;</button><span id="a11yFontSize">100%</span><button
              class="a11y-btn" id="a11yFontInc" aria-label="Increase font size"
              data-i18n-attr="aria-label:a11y_font_inc">A+</button></div>
        </div>
        <div class="a11y-row"><span class="a11y-label" data-i18n="a11y_high_contrast">High Contrast</span><label
            class="a11y-toggle-switch" aria-label="Toggle high contrast"
            data-i18n-attr="aria-label:a11y_high_contrast"><input type="checkbox" id="a11yContrast"><span
              class="a11y-slider"></span></label></div>
        <div class="a11y-row"><span class="a11y-label" data-i18n="a11y_grayscale">Grayscale</span><label
            class="a11y-toggle-switch" aria-label="Toggle grayscale" data-i18n-attr="aria-label:a11y_grayscale"><input
              type="checkbox" id="a11yGrayscale"><span class="a11y-slider"></span></label></div>
        <div class="a11y-row"><span class="a11y-label" data-i18n="a11y_reduce_motion">Reduce Motion</span><label
            class="a11y-toggle-switch" aria-label="Toggle reduce motion"
            data-i18n-attr="aria-label:a11y_reduce_motion"><input type="checkbox" id="a11yMotion"><span
              class="a11y-slider"></span></label></div>
      </div>
      <button id="a11yToggleBtn" aria-label="Open accessibility tools" aria-expanded="false" aria-controls="a11yPanel"
        data-i18n-attr="aria-label:a11y_toggle_btn">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10" />
          <circle cx="12" cy="7" r="1" fill="currentColor" stroke="none" />
          <path d="M9 17l1.5-4.5M15 17l-1.5-4.5M9 12.5h6" />
        </svg>
      </button>
    </div>
  <?php endif; ?>

  <?php if (!empty(SUPPORT_EMAIL) || !empty(SUPPORT_URL)): ?>
    <div class="help-fab-wrap" id="helpFabWrap">
      <button class="help-fab" type="button" id="helpFabBtn">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
          <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>
        <span data-i18n="need_help">Need help?</span>
      </button>
      <div class="help-menu" id="helpMenu">
        <a href="<?= !empty(SUPPORT_URL) ? htmlspecialchars(SUPPORT_URL) : 'mailto:' . htmlspecialchars(SUPPORT_EMAIL) ?>"
          target="_blank" data-i18n="contact_support">Contact Support</a>
        <a href="<?= htmlspecialchars(PANEL_URL) ?>" target="_blank" data-i18n="forgot_password">Forgot Password?</a>
      </div>
    </div>
  <?php endif; ?>

  <script>
    const html = document.documentElement;
    const themeBtn = document.getElementById('themeToggle');
    const iconSun = document.getElementById('iconSun');
    const iconMoon = document.getElementById('iconMoon');
    function applyTheme(t) {
      html.setAttribute('data-theme', t);
      iconSun.style.display = (t === 'dark') ? 'block' : 'none';
      iconMoon.style.display = (t === 'light') ? 'block' : 'none';
      localStorage.setItem('fp_theme', t);
    }
    let initTheme = localStorage.getItem('fp_theme') || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    applyTheme(initTheme);
    themeBtn.addEventListener('click', () => applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'));

    const I18N = {

      "en": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0yNTYgMGgyNTZ2NjRsLTMyIDMyIDMyIDMydjY0bC0zMiAzMiAzMiAzMnY2NGwtMzIgMzIgMzIgMzJ2NjRsLTI1NiAzMkwwIDQ0OHYtNjRsMzItMzItMzItMzJ2LTY0eiIvPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0yMjQgNjRoMjg4djY0SDIyNFptMCAxMjhoMjg4djY0SDI1NlpNMCAzMjBoNTEydjY0SDBabTAgMTI4aDUxMnY2NEgwWiIvPjxwYXRoIGZpbGw9IiMwMDUyYjQiIGQ9Ik0wIDBoMjU2djI1NkgwWiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Im0xODcgMjQzIDU3LTQxaC03MGw1NyA0MS0yMi02N3ptLTgxIDAgNTctNDFIOTNsNTcgNDEtMjItNjd6bS04MSAwIDU3LTQxSDEybDU3IDQxLTIyLTY3em0xNjItODEgNTctNDFoLTcwbDU3IDQxLTIyLTY3em0tODEgMCA1Ny00MUg5M2w1NyA0MS0yMi02N3ptLTgxIDAgNTctNDFIMTJsNTcgNDEtMjItNjdabTE2Mi04MiA1Ny00MWgtNzBsNTcgNDEtMjItNjdabS04MSAwIDU3LTQxSDkzbDU3IDQxLTIyLTY3em0tODEgMCA1Ny00MUgxMmw1NyA0MS0yMi02N1oiLz48L2c+PC9zdmc+",
        "name": "English",
        "subtitle": "web control panel",
        "username": "Username",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Email Address",
        "email_ph": "user@example.com",
        "password": "Password",
        "password_ph": "Min. 8 chars",
        "confirm": "Confirm",
        "confirm_ph": "Repeat",
        "register": "Log in",
        "already_registered": "Already registered?",
        "to_login": "To Login",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Weak",
        "pw_medium": "Medium",
        "pw_strong": "Strong",
        "please_wait": "Please wait...",
        "success_heading": "Account Created!",
        "generate": "Generate",
        "maintenance_heading": "Maintenance Mode",
        "maintenance_text": "New registrations are temporarily paused. Please check back later.",
        "tos_prefix": "I agree to the",
        "tos_link": "Terms of Service",
        "tos_and": "and",
        "privacy_link": "Privacy Policy",
        "did_you_mean": "Did you mean",
        "setup_2fa": "We recommend enabling Two-Factor Authentication (2FA) in the panel.",
        "copy_pw": "Copy",
        "need_help": "Need Help?",
        "contact_support": "Contact Support",
        "forgot_password": "Forgot Password?",
        "pw_req_length": "At least {n}characters",
        "pw_req_upper": "One uppercase (A-Z)",
        "pw_req_lower": "One lowercase (a-z)",
        "pw_req_number": "One number (0-9)",
        "email_mx_invalid": "The email domain does not appear to accept mail.",
        "pw_hibp_warning": "⚠️ This password appeared in {n} data breach(es).",
        "pw_hibp_ok": "✓ Password not found in known data breaches.",
        "pw_hibp_checking": "Checking password security...",
        "invite_code": "Invitation Code",
        "invite_code_ph": "Enter your invite code",
        "invite_invalid": "Invalid or already used invitation code.",
        "demo_notice": "⏱ This is a demo account and will be automatically deleted after {n} hour(s).",
        "domain": "Domain",
        "domain_ph": "example.com",
        "domain_notice": "Add your domain in the control panel after registering.",
        "to_panel": "To Panel",
        "invite_required": "An invitation code is required to register.",
        "cookie_banner_text": "We use essential cookies for security (CSRF, session). By continuing, you agree to our cookie usage.",
        "cookie_banner_btn": "Accept & Continue",
        "cookie_banner_label": "Cookie consent",
        "a11y_widget_label": "Accessibility tools",
        "a11y_panel_label": "Accessibility options",
        "a11y_title": "Accessibility",
        "a11y_font_size": "Font Size",
        "a11y_font_dec": "Decrease font size",
        "a11y_font_inc": "Increase font size",
        "a11y_high_contrast": "High Contrast",
        "a11y_grayscale": "Grayscale",
        "a11y_reduce_motion": "Reduce Motion",
        "a11y_toggle_btn": "Open accessibility tools"
        ,
        "cookie_text": "This website uses cookies to ensure you get the best experience.",
        "cookie_btn": "Got it!",
        "acc_title": "Accessibility",
        "acc_font": "Font Size",
        "acc_contrast": "High Contrast",
        "acc_grayscale": "Grayscale",
        "acc_motion": "Reduce Motion",
        "need_help": "Need help?"
      },
      "de": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0wIDM0NSAyNTYuNy0yNS41TDUxMiAzNDV2MTY3SDB6Ii8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0ibTAgMTY3IDI1NS0yMyAyNTcgMjN2MTc4SDB6Ii8+PHBhdGggZmlsbD0iIzMzMyIgZD0iTTAgMGg1MTJ2MTY3SDB6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Deutsch",
        "subtitle": "Web-Control-Panel",
        "username": "Benutzername",
        "username_ph": "4–8 Zeichen, a-z 0-9",
        "email": "E-Mail-Adresse",
        "email_ph": "user@example.com",
        "password": "Passwort",
        "password_ph": "Mind. 8 Zeichen",
        "confirm": "Bestätigen",
        "confirm_ph": "Wiederholen",
        "register": "Einloggen",
        "already_registered": "Bereits registriert?",
        "to_login": "Zum Login",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Schwach",
        "pw_medium": "Mittel",
        "pw_strong": "Stark",
        "please_wait": "Bitte warten...",
        "success_heading": "Konto erstellt!",
        "generate": "Erzeugen",
        "maintenance_heading": "Wartungsmodus",
        "maintenance_text": "Neu-Registrierungen sind vorübergehend pausiert. Bitte versuche es später erneut.",
        "tos_prefix": "Ich akzeptiere die",
        "tos_link": "Nutzungsbedingungen",
        "tos_and": "und die",
        "privacy_link": "Datenschutzerklärung",
        "did_you_mean": "Meintest du",
        "setup_2fa": "Wir empfehlen, die Zwei-Faktor-Authentifizierung (2FA) zu aktivieren.",
        "copy_pw": "Kopieren",
        "need_help": "Brauchst du Hilfe?",
        "contact_support": "Support kontaktieren",
        "forgot_password": "Passwort vergessen?",
        "pw_req_length": "Mindestens {n}Zeichen",
        "pw_req_upper": "Ein Großbuchstabe (A-Z)",
        "pw_req_lower": "Ein Kleinbuchstabe (a-z)",
        "pw_req_number": "Eine Zahl (0-9)",
        "email_mx_invalid": "Die E-Mail-Domain scheint keine E-Mails zu empfangen.",
        "pw_hibp_warning": "⚠️ Dieses Passwort tauchte in {n} Datenlecks auf.",
        "pw_hibp_ok": "✓ Passwort nicht in bekannten Datenlecks gefunden.",
        "pw_hibp_checking": "Passwortsicherheit wird geprüft...",
        "invite_code": "Einladungscode",
        "invite_code_ph": "Code eingeben",
        "invite_invalid": "Ungültiger oder bereits verwendeter Einladungscode.",
        "demo_notice": "⏱ Dies ist ein Demo-Konto und wird nach {n} Stunde(n) automatisch gelöscht.",
        "domain": "Domain",
        "domain_ph": "beispiel.de",
        "domain_notice": "Füge deine Domain nach der Registrierung im Control-Panel hinzu.",
        "to_panel": "Zum Panel",
        "invite_required": "Zur Registrierung ist ein Einladungscode erforderlich.",
        "cookie_banner_text": "Wir verwenden essenzielle Cookies für die Sicherheit (CSRF, Sitzung). Durch die Fortsetzung stimmen Sie unserer Cookie-Nutzung zu.",
        "cookie_banner_btn": "Akzeptieren & Fortfahren",
        "cookie_banner_label": "Cookie-Einwilligung",
        "a11y_widget_label": "Barrierefreiheit-Tools",
        "a11y_panel_label": "Barrierefreiheit-Optionen",
        "a11y_title": "Barrierefreiheit",
        "a11y_font_size": "Schriftgröße",
        "a11y_font_dec": "Schriftgröße verkleinern",
        "a11y_font_inc": "Schriftgröße vergrößern",
        "a11y_high_contrast": "Hoher Kontrast",
        "a11y_grayscale": "Graustufen",
        "a11y_reduce_motion": "Bewegung reduzieren",
        "a11y_toggle_btn": "Barrierefreiheit-Tools öffnen"
        ,
        "cookie_text": "Diese Website verwendet Cookies, um die beste Erfahrung zu gewährleisten.",
        "cookie_btn": "Verstanden!",
        "acc_title": "Barrierefreiheit",
        "acc_font": "Schriftgröße",
        "acc_contrast": "Hoher Kontrast",
        "acc_grayscale": "Graustufen",
        "acc_motion": "Bewegung reduzieren",
        "need_help": "Brauchen Sie Hilfe?"
      },
      "fr": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0xNjcgMGgxNzhsMjUuOSAyNTIuM0wzNDUgNTEySDE2N2wtMjkuOC0yNTMuNHoiLz48cGF0aCBmaWxsPSIjMDA1MmI0IiBkPSJNMCAwaDE2N3Y1MTJIMHoiLz48cGF0aCBmaWxsPSIjZDgwMDI3IiBkPSJNMzQ1IDBoMTY3djUxMkgzNDV6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Français",
        "subtitle": "panneau de contrôle web",
        "username": "Nom d'utilisateur",
        "username_ph": "4–8 caract., a-z 0-9",
        "email": "Adresse e-mail",
        "email_ph": "user@example.com",
        "password": "Mot de passe",
        "password_ph": "Min. 8 caract.",
        "confirm": "Confirmer",
        "confirm_ph": "Répéter",
        "register": "Connexion",
        "already_registered": "Déjà inscrit ?",
        "to_login": "Connexion",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Faible",
        "pw_medium": "Moyen",
        "pw_strong": "Fort",
        "please_wait": "Veuillez patienter...",
        "success_heading": "Compte créé !",
        "generate": "Générer",
        "maintenance_heading": "Mode maintenance",
        "maintenance_text": "Les nouvelles inscriptions sont temporairement suspendues.",
        "tos_prefix": "J'accepte les",
        "tos_link": "Conditions d'utilisation",
        "tos_and": "et la",
        "privacy_link": "Politique de confidentialité",
        "did_you_mean": "Vouliez-vous dire",
        "setup_2fa": "Nous recommandons d'activer l'authentification à deux facteurs (2FA).",
        "copy_pw": "Copier",
        "need_help": "Besoin d'aide ?",
        "contact_support": "Contacter le support",
        "forgot_password": "Mot de passe oublié ?",
        "pw_req_length": "Au moins {n}caractères",
        "pw_req_upper": "Une majuscule (A-Z)",
        "pw_req_lower": "Une minuscule (a-z)",
        "pw_req_number": "Un chiffre (0-9)",
        "email_mx_invalid": "Le domaine e-mail ne semble pas recevoir de courriels.",
        "pw_hibp_warning": "⚠️ Ce mot de passe est apparu dans {n} fuites.",
        "pw_hibp_ok": "✓ Mot de passe non trouvé dans les fuites connues.",
        "pw_hibp_checking": "Vérification en cours...",
        "invite_code": "Code d'invitation",
        "invite_code_ph": "Entrez votre code d'invitation",
        "invite_invalid": "Code invalide ou déjà utilisé.",
        "demo_notice": "⏱ Ce compte sera supprimé après {n} heure(s).",
        "domain": "Domaine",
        "domain_ph": "exemple.com",
        "domain_notice": "Ajoutez votre domaine dans le panneau de contrôle après votre inscription.",
        "to_panel": "Au panneau",
        "invite_required": "Un code d'invitation est requis pour s'inscrire.",
        "cookie_banner_text": "Nous utilisons des cookies essentiels pour la sécurité (CSRF, session). En continuant, vous acceptez notre utilisation des cookies.",
        "cookie_banner_btn": "Accepter et continuer",
        "cookie_banner_label": "Consentement aux cookies",
        "a11y_widget_label": "Outils d'accessibilité",
        "a11y_panel_label": "Options d'accessibilité",
        "a11y_title": "Accessibilité",
        "a11y_font_size": "Taille de police",
        "a11y_font_dec": "Réduire la taille de la police",
        "a11y_font_inc": "Augmenter la taille de la police",
        "a11y_high_contrast": "Contraste élevé",
        "a11y_grayscale": "Niveaux de gris",
        "a11y_reduce_motion": "Réduire les mouvements",
        "a11y_toggle_btn": "Ouvrir les outils d'accessibilité"
        ,
        "cookie_text": "Ce site utilise des cookies pour vous garantir la meilleure expérience.",
        "cookie_btn": "Compris !",
        "acc_title": "Accessibilité",
        "acc_font": "Taille de la police",
        "acc_contrast": "Contraste élevé",
        "acc_grayscale": "Niveaux de gris",
        "acc_motion": "Réduire le mouvement",
        "need_help": "Besoin d'aide ?"
      },
      "es": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0wIDEyOCAyNTYtMzIgMjU2IDMydjI1NmwtMjU2IDMyTDAgMzg0WiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0xOTYgMTY4cS0xMSAxLTE1IDExbC01LTFxLTE1IDEtMTYgMTZjLTEgMTUgNyAxNiAxNiAxNnExMSAwIDE1LTExYTE2IDE2IDAgMCAwIDE3LTQgMTYgMTYgMCAwIDAgMTcgNCAxNiAxNiAwIDEgMCAxMC0yMCAxNiAxNiAwIDAgMC0yNy01cS00LTYtMTItNm0wIDhxOCAxIDggOCAwIDgtOCA4LTcgMC04LTggMS03IDgtOG0yNCAwcTggMSA4IDggMCA4LTggOC03IDAtOC04IDEtNyA4LThtLTQ0IDEwIDQgMSA0IDhxLTEgNy04IDctOSAwLTgtOCAxLTcgOC04bTY0IDBxOCAxIDggOCAwIDgtOCA4LTcgMC04LTdsNC04em0tMTEyIDM4djgwaDE2di04MHptODAgMHY0MGMtMjYgMC00OCAxNC00OCAzMnMyMiAzMiA0OCAzMiA0OC0xNCA0OC0zMnYtNzJ6bTY0IDB2ODBoMTZ2LTgweiIvPjxwYXRoIGZpbGw9IiNmZjk4MTEiIGQ9Ik0yMDAgMTYwaDE2djMyaC0xNnoiLz48cGF0aCBmaWxsPSIjZDgwMDI3IiBkPSJNMCAwdjEyOGg1MTJWMHptMjA4IDE4NGMtMjIgMC00MCAxMS00MCAyNGw4IDhoNjRsOC04YzAtMTMtMTgtMjQtNDAtMjRtLTcyIDhhOCA4IDAgMCAwLTggOHY4YTggOCAwIDEgMCAxNiAwdi04YTggOCAwIDAgMC04LThtMTQ0IDBhOCA4IDAgMCAwLTggOHY4YTggOCAwIDEgMCAxNiAwdi04YTggOCAwIDAgMC04LThtLTEyMCAzMnYyNGgtMzhhNCA0IDAgMCAwLTQgNCA0IDQgMCAwIDAgNCA0aDM4djQwYTI0IDI0IDAgMCAwIDI0IDI0IDI0IDI0IDAgMCAwIDI0LTI0IDI0IDI0IDAgMCAwIDI0IDI0IDI0IDI0IDAgMCAwIDI0LTI0di0yNGgtNDh2LTQ4em03MiA4YTEwIDEwIDAgMCAwLTEwIDEwdjEyYTEwIDEwIDAgMSAwIDIwIDB2LTEyYTEwIDEwIDAgMCAwLTEwLTEwbTI0IDE2djhoMzhhNCA0IDAgMCAwIDQtNCA0IDQgMCAwIDAtNC00em0tMTM0IDI0YTQgNCAwIDAgMC00IDQgNCA0IDAgMCAwIDQgNGgyOGE0IDQgMCAwIDAgNC00IDQgNCAwIDAgMC00LTR6bTE0NCAwYTQgNCAwIDAgMC00IDQgNCA0IDAgMCAwIDQgNGgyOGE0IDQgMCAwIDAgNC00IDQgNCAwIDAgMC00LTR6TTAgMzg0djEyOGg1MTJWMzg0eiIvPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Ik0xODYgMTk2YTYgNiAwIDAgMC02IDYgNiA2IDAgMCAwIDYgNiA2IDYgMCAwIDAgNi02IDYgNiAwIDAgMC02LTZtMjIgMGE2IDYgMCAwIDAtNiA2IDYgNiAwIDAgMCA2IDYgNiA2IDAgMCAwIDYtNiA2IDYgMCAwIDAtNi02bTIyIDBhNiA2IDAgMCAwLTYgNiA2IDYgMCAwIDAgNiA2IDYgNiAwIDAgMCA2LTYgNiA2IDAgMCAwLTYtNiIvPjxwYXRoIGZpbGw9IiNmZjk4MTEiIGQ9Ik0xMjggMjA4YTggOCAwIDEgMCAwIDE2aDE2YTggOCAwIDEgMCAwLTE2em0xNDQgMGE4IDggMCAxIDAgMCAxNmgxNmE4IDggMCAxIDAgMC0xNnptLTk2IDh2OGg2NHYtOHptLTggMTZ2OGg4djE2aC04djhoMzJ2LThoLTh2LTE2aDh2LTh6bS04IDQwdjI0cTEgMTIgOSAxOXYtNDN6bTE5IDB2NDdoMTB2LTQ3em0yMCAwdjQzcTktNyA5LTE5di0yNHptLTcxIDMyYTggOCAwIDEgMCAwIDE2aDE2YTggOCAwIDEgMCAwLTE2em0xNDQgMGE4IDggMCAxIDAgMCAxNmgxNmE4IDggMCAxIDAgMC0xNnoiLz48cGF0aCBmaWxsPSIjMzM4YWYzIiBkPSJNMjA4IDI1NmExNiAxNiAwIDAgMC0xNiAxNiAxNiAxNiAwIDAgMCAxNiAxNiAxNiAxNiAwIDAgMCAxNi0xNiAxNiAxNiAwIDAgMC0xNi0xNm0tODAgNjRhOCA4IDAgMSAwIDAgMTZoMTZhOCA4IDAgMSAwIDAtMTZ6bTE0NCAwYTggOCAwIDEgMCAwIDE2aDE2YTggOCAwIDEgMCAwLTE2eiIvPjwvZz48L3N2Zz4=",
        "name": "Español",
        "subtitle": "panel de control web",
        "username": "Nombre de usuario",
        "username_ph": "4–8 caráct., a-z 0-9",
        "email": "Correo electrónico",
        "email_ph": "usuario@ejemplo.com",
        "password": "Contraseña",
        "password_ph": "Mín. 8 caráct.",
        "confirm": "Confirmar",
        "confirm_ph": "Repetir",
        "register": "Iniciar sesión",
        "already_registered": "¿Ya estás registrado?",
        "to_login": "Iniciar sesión",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Débil",
        "pw_medium": "Medio",
        "pw_strong": "Fuerte",
        "please_wait": "Por favor, espere...",
        "success_heading": "¡Cuenta creada!",
        "generate": "Generar",
        "maintenance_heading": "Modo de mantenimiento",
        "maintenance_text": "Los nuevos registros están en pausa temporalmente.",
        "tos_prefix": "Acepto los",
        "tos_link": "Términos de servicio",
        "tos_and": "y la",
        "privacy_link": "Política de privacidad",
        "did_you_mean": "¿Quisiste decir",
        "setup_2fa": "Recomendamos habilitar la autenticación de dos factores (2FA).",
        "copy_pw": "Copiar",
        "need_help": "¿Necesitas ayuda?",
        "contact_support": "Contactar a soporte",
        "forgot_password": "¿Olvidaste tu contraseña?",
        "pw_req_length": "Al menos {n}caracteres",
        "pw_req_upper": "Una mayúscula (A-Z)",
        "pw_req_lower": "Una minúscula (a-z)",
        "pw_req_number": "Un número (0-9)",
        "email_mx_invalid": "El dominio de correo no parece aceptar correos.",
        "pw_hibp_warning": "⚠️ Esta contraseña apareció en {n} filtraciones.",
        "pw_hibp_ok": "✓ Contraseña no encontrada en filtraciones conocidas.",
        "pw_hibp_checking": "Comprobando la seguridad...",
        "invite_code": "Código de invitación",
        "invite_code_ph": "Ingresa tu código de invitación",
        "invite_invalid": "Código inválido o ya usado.",
        "demo_notice": "⏱ Esta cuenta será eliminada después de {n} hora(s).",
        "domain": "Dominio",
        "domain_ph": "ejemplo.com",
        "domain_notice": "Añade tu dominio en el panel de control después de registrarte.",
        "to_panel": "Al panel",
        "invite_required": "Se requiere un código de invitación para registrarse.",
        "cookie_banner_text": "Utilizamos cookies esenciales para la seguridad (CSRF, sesión). Al continuar, aceptas nuestro uso de cookies.",
        "cookie_banner_btn": "Aceptar y continuar",
        "cookie_banner_label": "Consentimiento de cookies",
        "a11y_widget_label": "Herramientas de accesibilidad",
        "a11y_panel_label": "Opciones de accesibilidad",
        "a11y_title": "Accesibilidad",
        "a11y_font_size": "Tamaño de fuente",
        "a11y_font_dec": "Disminuir tamaño de fuente",
        "a11y_font_inc": "Aumentar tamaño de fuente",
        "a11y_high_contrast": "Alto contraste",
        "a11y_grayscale": "Escala de grises",
        "a11y_reduce_motion": "Reducir movimiento",
        "a11y_toggle_btn": "Abrir herramientas de accesibilidad"
        ,
        "cookie_text": "Este sitio web utiliza cookies para garantizar que obtenga la mejor experiencia.",
        "cookie_btn": "¡Entendido!",
        "acc_title": "Accesibilidad",
        "acc_font": "Tamaño de fuente",
        "acc_contrast": "Alto contraste",
        "acc_grayscale": "Escala de grises",
        "acc_motion": "Reducir movimiento",
        "need_help": "¿Necesitas ayuda?"
      },
      "et": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiMzMzMiIGQ9Im0wIDE2NyAyNTQuNi0zNi42TDUxMiAxNjYuOXYxNzhsLTI1NC42IDM2LjRMMCAzNDQuOXoiLz48cGF0aCBmaWxsPSIjMDA1MmI0IiBkPSJNMCAwaDUxMnYxNjYuOUgweiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0wIDM0NC45aDUxMlY1MTJIMHoiLz48L2c+PC9zdmc+",
        "name": "Eesti",
        "subtitle": "veebi juhtpaneel",
        "username": "Kasutajanimi",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "E-posti aadress",
        "email_ph": "user@example.com",
        "password": "Salasõna",
        "password_ph": "Min. 8 chars",
        "confirm": "Kinnita",
        "confirm_ph": "Repeat",
        "register": "Logi sisse",
        "already_registered": "Juba registreeritud?",
        "to_login": "Logi sisse",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Nõrk",
        "pw_medium": "Keskmine",
        "pw_strong": "Tugev",
        "please_wait": "Palun oota...",
        "success_heading": "Konto on loodud!",
        "generate": "Genereeri",
        "maintenance_heading": "Hooldusrežiim",
        "maintenance_text": "Uued registreerimised on ajutiselt peatatud.",
        "tos_prefix": "Nõustun",
        "tos_link": "Kasutustingimustega",
        "tos_and": "ja",
        "privacy_link": "Privaatsuspoliitikaga",
        "did_you_mean": "Kas pidasid silmas",
        "setup_2fa": "Soovitame lubada kaheastmelise autentimise (2FA).",
        "copy_pw": "Kopeeri",
        "need_help": "Vajad abi?",
        "contact_support": "Võta ühendust toega",
        "forgot_password": "Unustasid parooli?",
        "pw_req_length": "Vähemalt {n} tähemärki",
        "pw_req_upper": "Üks suurtäht (A-Z)",
        "pw_req_lower": "Üks väiketäht (a-z)",
        "pw_req_number": "Üks number (0-9)",
        "email_mx_invalid": "E-posti domeen ei paista kirju vastu võtvat.",
        "pw_hibp_warning": "⚠️ See parool esines {n} andmelekkes.",
        "pw_hibp_ok": "✓ Parooli ei leitud teadaolevatest andmeleketest.",
        "pw_hibp_checking": "Kontrollime parooli turvalisust...",
        "invite_code": "Kutsekood",
        "invite_code_ph": "Sisesta oma kutsekood",
        "invite_invalid": "Vigane või juba kasutatud kutsekood.",
        "demo_notice": "⏱ See demokonto kustutatakse {n} tunni pärast.",
        "domain": "Domen",
        "domain_ph": "naide.ee",
        "domain_notice": "Lisa oma domeen pärast registreerumist juhtpaneelis.",
        "to_panel": "Juhtpaneelile",
        "invite_required": "Registreerumiseks on vajalik kutsekood.",
        "cookie_banner_text": "Kasutame turvalisuse tagamiseks hädavajalikke küpsiseid (CSRF, sessioon). Jätkates nõustud küpsiste kasutamisega.",
        "cookie_banner_btn": "Nõustu ja jätka",
        "cookie_banner_label": "Küpsiste nõusolek",
        "a11y_widget_label": "Juurdepääsetavuse tööriistad",
        "a11y_panel_label": "Juurdepääsetavuse valikud",
        "a11y_title": "Juurdepääsetavus",
        "a11y_font_size": "Kirja suurus",
        "a11y_font_dec": "Vähenda kirja suurust",
        "a11y_font_inc": "Suurenda kirja suurust",
        "a11y_high_contrast": "Kõrge kontrastsus",
        "a11y_grayscale": "Halltoonid",
        "a11y_reduce_motion": "Vähenda liikumist",
        "a11y_toggle_btn": "Ava juurdepääsetavuse tööriistad"
      },
      "id": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Im0wIDI1NiAyNDkuNi00MS4zTDUxMiAyNTZ2MjU2SDB6Ii8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0iTTAgMGg1MTJ2MjU2SDB6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Indonesian",
        "subtitle": "panel kontrol web",
        "username": "Nama Pengguna",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Alamat Email",
        "email_ph": "user@example.com",
        "password": "Kata Sandi",
        "password_ph": "Min. 8 chars",
        "confirm": "Konfirmasi",
        "confirm_ph": "Repeat",
        "register": "Masuk",
        "already_registered": "Sudah terdaftar?",
        "to_login": "Masuk",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Lemah",
        "pw_medium": "Sedang",
        "pw_strong": "Kuat",
        "please_wait": "Harap tunggu...",
        "success_heading": "Akun Dibuat!",
        "generate": "Hasilkan",
        "maintenance_heading": "Mode Pemeliharaan",
        "maintenance_text": "Pendaftaran baru ditangguhkan sementara.",
        "tos_prefix": "Saya setuju dengan",
        "tos_link": "Ketentuan Layanan",
        "tos_and": "dan",
        "privacy_link": "Kebijakan Privasi",
        "did_you_mean": "Maksud Anda",
        "setup_2fa": "Kami menyarankan untuk mengaktifkan 2FA.",
        "copy_pw": "Salin",
        "need_help": "Butuh Bantuan?",
        "contact_support": "Hubungi Dukungan",
        "forgot_password": "Lupa Kata Sandi?",
        "pw_req_length": "Minimal {n}karakter",
        "pw_req_upper": "Satu huruf besar (A-Z)",
        "pw_req_lower": "Satu huruf kecil (a-z)",
        "pw_req_number": "Satu angka (0-9)",
        "email_mx_invalid": "Domain email sepertinya tidak menerima pesan.",
        "pw_hibp_warning": "⚠️ Kata sandi ini muncul dalam {n} kebocoran.",
        "pw_hibp_ok": "✓ Kata sandi tidak ditemukan dalam kebocoran.",
        "pw_hibp_checking": "Memeriksa keamanan kata sandi...",
        "invite_code": "Kode Undangan",
        "invite_code_ph": "Masukkan kode undangan",
        "invite_invalid": "Kode undangan tidak valid atau sudah digunakan.",
        "demo_notice": "⏱ Akun demo ini akan dihapus setelah {n} jam.",
        "domain": "Domain",
        "domain_ph": "contoh.com",
        "domain_notice": "Tambahkan domain Anda di panel kontrol setelah mendaftar.",
        "to_panel": "Ke Panel",
        "invite_required": "Kode undangan diperlukan untuk mendaftar.",
        "cookie_banner_text": "Kami menggunakan cookie esensial untuk keamanan (CSRF, sesi). Dengan melanjutkan, Anda menyetujui penggunaan cookie kami.",
        "cookie_banner_btn": "Terima & Lanjutkan",
        "cookie_banner_label": "Persetujuan cookie",
        "a11y_widget_label": "Alat aksesibilitas",
        "a11y_panel_label": "Opsi aksesibilitas",
        "a11y_title": "Aksesibilitas",
        "a11y_font_size": "Ukuran Font",
        "a11y_font_dec": "Kecilkan ukuran font",
        "a11y_font_inc": "Besarkan ukuran font",
        "a11y_high_contrast": "Kontras Tinggi",
        "a11y_grayscale": "Skala Abu-abu",
        "a11y_reduce_motion": "Kurangi Gerakan",
        "a11y_toggle_btn": "Buka alat aksesibilitas"
        ,
        "cookie_text": "Situs web ini menggunakan cookie untuk memastikan Anda mendapatkan pengalaman terbaik.",
        "cookie_btn": "Mengerti!",
        "acc_title": "Aksesibilitas",
        "acc_font": "Ukuran Font",
        "acc_contrast": "Kontras Tinggi",
        "acc_grayscale": "Skala Abu-abu",
        "acc_motion": "Kurangi Gerakan",
        "need_help": "Butuh bantuan?"
      },
      "it": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0xNjcgMGgxNzhsMjUuOSAyNTIuM0wzNDUgNTEySDE2N2wtMjkuOC0yNTMuNHoiLz48cGF0aCBmaWxsPSIjNmRhNTQ0IiBkPSJNMCAwaDE2N3Y1MTJIMHoiLz48cGF0aCBmaWxsPSIjZDgwMDI3IiBkPSJNMzQ1IDBoMTY3djUxMkgzNDV6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Italiano",
        "subtitle": "pannello di controllo",
        "username": "Nome utente",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Indirizzo Email",
        "email_ph": "user@example.com",
        "password": "Password",
        "password_ph": "Min. 8 chars",
        "confirm": "Conferma",
        "confirm_ph": "Repeat",
        "register": "Accedi",
        "already_registered": "Già registrato?",
        "to_login": "Accedi",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Debole",
        "pw_medium": "Media",
        "pw_strong": "Forte",
        "please_wait": "Attendere...",
        "success_heading": "Account Creato!",
        "generate": "Genera",
        "maintenance_heading": "Modalità di manutenzione",
        "maintenance_text": "Le nuove registrazioni sono momentaneamente in pausa.",
        "tos_prefix": "Accetto i",
        "tos_link": "Termini di Servizio",
        "tos_and": "e la",
        "privacy_link": "Informativa sulla Privacy",
        "did_you_mean": "Intendevi",
        "setup_2fa": "Consigliamo di abilitare l'autenticazione a due fattori (2FA).",
        "copy_pw": "Copia",
        "need_help": "Serve aiuto?",
        "contact_support": "Contatta il supporto",
        "forgot_password": "Password dimenticata?",
        "pw_req_length": "Almeno {n}caratteri",
        "pw_req_upper": "Una maiuscola (A-Z)",
        "pw_req_lower": "Una minuscola (a-z)",
        "pw_req_number": "Un numero (0-9)",
        "email_mx_invalid": "Il dominio email non sembra accettare messaggi.",
        "pw_hibp_warning": "⚠️ Questa password è apparsa in {n} violazioni.",
        "pw_hibp_ok": "✓ Password non trovata nelle violazioni.",
        "pw_hibp_checking": "Verifica della sicurezza in corso...",
        "invite_code": "Codice di invito",
        "invite_code_ph": "Inserisci il codice di invito",
        "invite_invalid": "Codice invito non valido o già utilizzato.",
        "demo_notice": "⏱ Questo account demo verrà eliminato tra {n} ora/e.",
        "domain": "Dominio",
        "domain_ph": "esempio.com",
        "domain_notice": "Aggiungi il tuo dominio nel pannello di controllo dopo la registrazione.",
        "to_panel": "Al Pannello",
        "invite_required": "È richiesto un codice di invito per registrarsi.",
        "cookie_banner_text": "Utilizziamo cookie essenziali per la sicurezza (CSRF, sessione). Continuando, accetti il nostro utilizzo dei cookie.",
        "cookie_banner_btn": "Accetta e continua",
        "cookie_banner_label": "Consenso sui cookie",
        "a11y_widget_label": "Strumenti di accessibilità",
        "a11y_panel_label": "Opzioni di accessibilità",
        "a11y_title": "Accessibilità",
        "a11y_font_size": "Dimensione carattere",
        "a11y_font_dec": "Riduci dimensione carattere",
        "a11y_font_inc": "Aumenta dimensione carattere",
        "a11y_high_contrast": "Contrasto elevato",
        "a11y_grayscale": "Scala di grigi",
        "a11y_reduce_motion": "Riduci movimento",
        "a11y_toggle_btn": "Apri strumenti di accessibilità"
        ,
        "cookie_text": "Questo sito Web utilizza i cookie per assicurarti la migliore esperienza.",
        "cookie_btn": "Capito!",
        "acc_title": "Accessibilità",
        "acc_font": "Dimensione del carattere",
        "acc_contrast": "Contrasto elevato",
        "acc_grayscale": "Scala di grigi",
        "acc_motion": "Riduci movimento",
        "need_help": "Serve aiuto?"
      },
      "lt": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiM2ZGE1NDQiIGQ9Im0wIDE2NyAyNTMuOC0xOS4zTDUxMiAxNjd2MTc4bC0yNTQuOSAzMi4zTDAgMzQ1eiIvPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Ik0wIDBoNTEydjE2N0gweiIvPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDM0NWg1MTJ2MTY3SDB6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Lietuvių",
        "subtitle": "žiniatinklio valdymo skydelis",
        "username": "Vartotojo vardas",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "El. paštas",
        "email_ph": "user@example.com",
        "password": "Slaptažodis",
        "password_ph": "Min. 8 chars",
        "confirm": "Patvirtinti",
        "confirm_ph": "Repeat",
        "register": "Prisijungti",
        "already_registered": "Jau užsiregistravę?",
        "to_login": "Prisijungti",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Silpnas",
        "pw_medium": "Vidutinis",
        "pw_strong": "Stiprus",
        "please_wait": "Prašome palaukti...",
        "success_heading": "Paskyra sukurta!",
        "generate": "Generuoti",
        "maintenance_heading": "Priežiūros režimas",
        "maintenance_text": "Naujos registracijos laikinai sustabdytos.",
        "tos_prefix": "Sutinku su",
        "tos_link": "Paslaugų teikimo sąlygomis",
        "tos_and": "ir",
        "privacy_link": "Privatumo politika",
        "did_you_mean": "Ar turėjote omenyje",
        "setup_2fa": "Rekomenduojame įjungti dviejų veiksnių autentifikavimą (2FA).",
        "copy_pw": "Kopijuoti",
        "need_help": "Reikia pagalbos?",
        "contact_support": "Susisiekite su pagalba",
        "forgot_password": "Pamiršote slaptažodį?",
        "pw_req_length": "Mažiausiai {n}simbolių",
        "pw_req_upper": "Viena didžioji raidė (A-Z)",
        "pw_req_lower": "Viena mažoji raidė (a-z)",
        "pw_req_number": "Vienas skaičius (0-9)",
        "email_mx_invalid": "Atrodo, kad el. pašto domenas nepriima laiškų.",
        "pw_hibp_warning": "⚠️ Šis slaptažodis pasirodė {n} nutekėjimuose.",
        "pw_hibp_ok": "✓ Slaptažodis nerastas nutekėjimuose.",
        "pw_hibp_checking": "Tikrinamas saugumas...",
        "invite_code": "Pakvietimo kodas",
        "invite_code_ph": "Įveskite pakvietimo kodą",
        "invite_invalid": "Neteisingas arba jau panaudotas pakvietimo kodas.",
        "demo_notice": "⏱ Ši demonstracinė paskyra bus ištrinta po {n} valandų.",
        "domain": "Domenas",
        "domain_ph": "pavyzdys.lt",
        "domain_notice": "Pridėkite savo domeną valdymo skydelyje po registracijos.",
        "to_panel": "Į skydelį",
        "invite_required": "Registracijai reikalingas pakvietimo kodas.",
        "cookie_banner_text": "Saugumui (CSRF, seansui) naudojame būtinus slapukus. Tęsdami sutinkate su slapukų naudojimu.",
        "cookie_banner_btn": "Sutikti ir tęsti",
        "cookie_banner_label": "Slapukų sutikimas",
        "a11y_widget_label": "Prieinamumo įrankiai",
        "a11y_panel_label": "Prieinamumo parinktys",
        "a11y_title": "Prieinamumas",
        "a11y_font_size": "Šrifto dydis",
        "a11y_font_dec": "Sumažinti šrifto dydį",
        "a11y_font_inc": "Padidinti šrifto dydį",
        "a11y_high_contrast": "Didelis kontrastas",
        "a11y_grayscale": "Pilkumo skalė",
        "a11y_reduce_motion": "Sumažinti judėjimą",
        "a11y_toggle_btn": "Atidaryti prieinamumo įrankius"
      },
      "pl": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Im0wIDI1NiAyNTYuNC00NC4zTDUxMiAyNTZ2MjU2SDB6Ii8+PHBhdGggZmlsbD0iI2VlZSIgZD0iTTAgMGg1MTJ2MjU2SDB6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Polski",
        "subtitle": "panel sterowania",
        "username": "Nazwa użytkownika",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Adres e-mail",
        "email_ph": "user@example.com",
        "password": "Hasło",
        "password_ph": "Min. 8 chars",
        "confirm": "Potwierdź",
        "confirm_ph": "Repeat",
        "register": "Zaloguj się",
        "already_registered": "Masz już konto?",
        "to_login": "Zaloguj się",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Słabe",
        "pw_medium": "Średnie",
        "pw_strong": "Silne",
        "please_wait": "Proszę czekać...",
        "success_heading": "Konto zostało utworzone!",
        "generate": "Generuj",
        "maintenance_heading": "Tryb konserwacji",
        "maintenance_text": "Nowe rejestracje są tymczasowo wstrzymane.",
        "tos_prefix": "Akceptuję",
        "tos_link": "Warunki świadczenia usług",
        "tos_and": "oraz",
        "privacy_link": "Politykę prywatności",
        "did_you_mean": "Czy chodziło Ci o",
        "setup_2fa": "Zalecamy włączenie uwierzytelniania dwuskładnikowego (2FA).",
        "copy_pw": "Kopiuj",
        "need_help": "Potrzebujesz pomocy?",
        "contact_support": "Skontaktuj się z pomocą",
        "forgot_password": "Zapomniałeś hasła?",
        "pw_req_length": "Co najmniej {n}znaków",
        "pw_req_upper": "Jedna wielka litera (A-Z)",
        "pw_req_lower": "Jedna mała litera (a-z)",
        "pw_req_number": "Jedna cyfra (0-9)",
        "email_mx_invalid": "Domena e-mail wydaje się nie przyjmować wiadomości.",
        "pw_hibp_warning": "⚠️ To hasło pojawiło się w {n} wyciekach.",
        "pw_hibp_ok": "✓ Hasło nie zostało znalezione w wyciekach.",
        "pw_hibp_checking": "Sprawdzanie bezpieczeństwa hasła...",
        "invite_code": "Kod zaproszenia",
        "invite_code_ph": "Wprowadź kod zaproszenia",
        "invite_invalid": "Nieprawidłowy lub już wykorzystany kod zaproszenia.",
        "demo_notice": "⏱ To jest konto demo i zostanie usunięte po {n} godzinach.",
        "domain": "Domena",
        "domain_ph": "przyklad.pl",
        "domain_notice": "Dodaj swoją domenę w panelu sterowania po zarejestrowaniu.",
        "to_panel": "Do panelu",
        "invite_required": "Kod zaproszenia jest wymagany do rejestracji.",
        "cookie_banner_text": "Używamy niezbędnych plików cookie dla bezpieczeństwa (CSRF, sesja). Kontynuując, zgadzasz się na użycie plików cookie.",
        "cookie_banner_btn": "Akceptuj i kontynuuj",
        "cookie_banner_label": "Zgoda na pliki cookie",
        "a11y_widget_label": "Narzędzia dostępności",
        "a11y_panel_label": "Opcje dostępności",
        "a11y_title": "Dostępność",
        "a11y_font_size": "Rozmiar czcionki",
        "a11y_font_dec": "Zmniejsz rozmiar czcionki",
        "a11y_font_inc": "Zwiększ rozmiar czcionki",
        "a11y_high_contrast": "Wysoki kontrast",
        "a11y_grayscale": "Skala szarości",
        "a11y_reduce_motion": "Zmniejsz ruch",
        "a11y_toggle_btn": "Otwórz narzędzia dostępności"
        ,
        "cookie_text": "Ta strona używa plików cookie, aby zapewnić najlepsze wrażenia.",
        "cookie_btn": "Rozumiem!",
        "acc_title": "Dostępność",
        "acc_font": "Rozmiar czcionki",
        "acc_contrast": "Wysoki kontrast",
        "acc_grayscale": "Skala szarości",
        "acc_motion": "Zmniejsz ruch",
        "need_help": "Potrzebujesz pomocy?"
      },
      "pt": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiM2ZGE1NDQiIGQ9Ik0wIDBoNTEydjUxMkgweiIvPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Ik0yNTYgMTAwLjIgNDY3LjUgMjU2IDI1NiA0MTEuOCA0NC41IDI1NnoiLz48cGF0aCBmaWxsPSIjZWVlIiBkPSJNMTc0LjIgMjIxYTg3IDg3IDAgMCAwLTcuMiAzNi4zbDE2MiA0OS44YTg4LjUgODguNSAwIDAgMCAxNC40LTM0Yy00MC42LTY1LjMtMTE5LjctODAuMy0xNjkuMS01MnoiLz48cGF0aCBmaWxsPSIjMDA1MmI0IiBkPSJNMjU1LjcgMTY3YTg5IDg5IDAgMCAwLTQxLjkgMTAuNiA4OSA4OSAwIDAgMC0zOS42IDQzLjQgMTgxLjcgMTgxLjcgMCAwIDEgMTY5LjEgNTIuMiA4OSA4OSAwIDAgMC05LTU5LjQgODkgODkgMCAwIDAtNzguNi00Ni44ek0yMTIgMjUwLjVhMTQ5IDE0OSAwIDAgMC00NSA2LjggODkgODkgMCAwIDAgMTAuNSA0MC45IDg5IDg5IDAgMCAwIDEyMC42IDM2LjIgODkgODkgMCAwIDAgMzAuNy0yNy4zQTE1MSAxNTEgMCAwIDAgMjEyIDI1MC41eiIvPjwvZz48L3N2Zz4=",
        "name": "Português (Brasil)",
        "subtitle": "painel de controle",
        "username": "Nome de Usuário",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Endereço de E-mail",
        "email_ph": "user@example.com",
        "password": "Senha",
        "password_ph": "Min. 8 chars",
        "confirm": "Confirmar",
        "confirm_ph": "Repeat",
        "register": "Entrar",
        "already_registered": "Já está registrado?",
        "to_login": "Entrar",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Fraca",
        "pw_medium": "Média",
        "pw_strong": "Forte",
        "please_wait": "Aguarde...",
        "success_heading": "Conta Criada!",
        "generate": "Gerar",
        "maintenance_heading": "Modo de Manutenção",
        "maintenance_text": "Novos registros estão temporariamente pausados.",
        "tos_prefix": "Eu concordo com os",
        "tos_link": "Termos de Serviço",
        "tos_and": "e a",
        "privacy_link": "Política de Privacidade",
        "did_you_mean": "Você quis dizer",
        "setup_2fa": "Recomendamos ativar a Autenticação de Dois Fatores (2FA).",
        "copy_pw": "Copiar",
        "need_help": "Precisa de ajuda?",
        "contact_support": "Contate o Suporte",
        "forgot_password": "Esqueceu a senha?",
        "pw_req_length": "Pelo menos {n}caracteres",
        "pw_req_upper": "Uma letra maiúscula (A-Z)",
        "pw_req_lower": "Uma letra minúscula (a-z)",
        "pw_req_number": "Um número (0-9)",
        "email_mx_invalid": "O domínio do e-mail não parece aceitar mensagens.",
        "pw_hibp_warning": "⚠️ Esta senha apareceu em {n} vazamentos.",
        "pw_hibp_ok": "✓ Senha não encontrada em vazamentos conhecidos.",
        "pw_hibp_checking": "Verificando segurança da senha...",
        "invite_code": "Código de Convite",
        "invite_code_ph": "Insira seu código de convite",
        "invite_invalid": "Código inválido ou já utilizado.",
        "demo_notice": "⏱ Esta conta demo será excluída após {n} hora(s).",
        "domain": "Domínio",
        "domain_ph": "exemplo.com",
        "domain_notice": "Adicione seu domínio no painel de controle após se registrar.",
        "to_panel": "Ir para o Painel",
        "invite_required": "Um código de convite é necessário para se registrar.",
        "cookie_banner_text": "Usamos cookies essenciais para segurança (CSRF, sessão). Ao continuar, você concorda com o uso de cookies.",
        "cookie_banner_btn": "Aceitar e continuar",
        "cookie_banner_label": "Consentimento de cookies",
        "a11y_widget_label": "Ferramentas de acessibilidade",
        "a11y_panel_label": "Opções de acessibilidade",
        "a11y_title": "Acessibilidade",
        "a11y_font_size": "Tamanho da fonte",
        "a11y_font_dec": "Diminuir tamanho da fonte",
        "a11y_font_inc": "Aumentar tamanho da fonte",
        "a11y_high_contrast": "Alto contraste",
        "a11y_grayscale": "Escala de cinza",
        "a11y_reduce_motion": "Reduzir movimento",
        "a11y_toggle_btn": "Abrir ferramentas de acessibilidade"
        ,
        "cookie_text": "Este site usa cookies para garantir que você tenha a melhor experiência.",
        "cookie_btn": "Entendi!",
        "acc_title": "Acessibilidade",
        "acc_font": "Tamanho da fonte",
        "acc_contrast": "Alto contraste",
        "acc_grayscale": "Escala de cinza",
        "acc_motion": "Reduzir movimento",
        "need_help": "Precisa de ajuda?"
      },
      "rs": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiMwMDUyYjQiIGQ9Im0wIDE2NyAyNTMuOC0xOS4zTDUxMiAxNjd2MTc4bC0yNTQuOSAzMi4zTDAgMzQ1eiIvPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoNTEydjE2N0gweiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0wIDM0NWg1MTJ2MTY3SDB6Ii8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0iTTY2LjIgMTQ0Ljd2MTI3LjdjMCA3Mi42IDk0LjkgOTUgOTQuOSA5NXM5NC45LTIyLjQgOTQuOS05NVYxNDQuN3oiLz48cGF0aCBmaWxsPSIjZmZkYTQ0IiBkPSJNMTA1LjQgMTY3aDExMS40di00NC42bC0yMi4zIDExLjItMzMuNC0zMy40LTMzLjQgMzMuNC0yMi4zLTExLjJ6bTEyOC4zIDEyMy4yLTcyLjMtNzIuNEw4OSAyOTAuMmwyMy43IDIzLjYgNDguNy00OC43IDQ4LjcgNDguN3oiLz48cGF0aCBmaWxsPSIjZWVlIiBkPSJNMjMzLjcgMjIyLjZIMjAwYTIyLjEgMjIuMSAwIDAgMCAzLTExLjEgMjIuMyAyMi4zIDAgMCAwLTQyLTEwLjUgMjIuMyAyMi4zIDAgMCAwLTQxLjkgMTAuNSAyMi4xIDIyLjEgMCAwIDAgMyAxMS4xSDg5YTIzIDIzIDAgMCAwIDIzIDIyLjNoLS43YzAgMTIuMyAxMCAyMi4yIDIyLjMgMjIuMiAwIDExIDcuOCAyMCAxOC4xIDIxLjlsLTE3LjUgMzkuNmE3Mi4xIDcyLjEgMCAwIDAgMjcuMiA1LjMgNzIuMSA3Mi4xIDAgMCAwIDI3LjItNS4zTDE3MS4xIDI4OWMxMC4zLTIgMTguMS0xMSAxOC4xLTIxLjkgMTIuMyAwIDIyLjMtMTAgMjIuMy0yMi4yaC0uOGEyMyAyMyAwIDAgMCAyMy0yMi4zeiIvPjwvZz48L3N2Zz4=",
        "name": "Srpski (latinica)",
        "subtitle": "kontrolni panel",
        "username": "Korisničko ime",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Email adresa",
        "email_ph": "user@example.com",
        "password": "Lozinka",
        "password_ph": "Min. 8 chars",
        "confirm": "Potvrdi",
        "confirm_ph": "Repeat",
        "register": "Prijavite se",
        "already_registered": "Već ste registrovani?",
        "to_login": "Prijavite se",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Slaba",
        "pw_medium": "Srednja",
        "pw_strong": "Jaka",
        "please_wait": "Sačekajte...",
        "success_heading": "Nalog je kreiran!",
        "generate": "Generiši",
        "maintenance_heading": "Režim održavanja",
        "maintenance_text": "Nove registracije su privremeno pauzirane.",
        "tos_prefix": "Slažem se sa",
        "tos_link": "Uslovima korišćenja",
        "tos_and": "i",
        "privacy_link": "Politikom privatnosti",
        "did_you_mean": "Da li ste mislili",
        "setup_2fa": "Preporučujemo da omogućite dvofaktorsku autentifikaciju (2FA).",
        "copy_pw": "Kopiraj",
        "need_help": "Treba vam pomoć?",
        "contact_support": "Kontaktirajte podršku",
        "forgot_password": "Zaboravili ste lozinku?",
        "pw_req_length": "Najmanje {n} karaktera",
        "pw_req_upper": "Jedno veliko slovo (A-Z)",
        "pw_req_lower": "Jedno malo slovo (a-z)",
        "pw_req_number": "Jedan broj (0-9)",
        "email_mx_invalid": "Email domen ne prihvata poruke.",
        "pw_hibp_warning": "⚠️ Ova lozinka se pojavila u {n} curenja podataka.",
        "pw_hibp_ok": "✓ Lozinka nije pronađena u poznatim curenjima.",
        "pw_hibp_checking": "Provera bezbednosti lozinke...",
        "invite_code": "Pozivni kod",
        "invite_code_ph": "Unesite pozivni kod",
        "invite_invalid": "Nevažeći ili već iskorišćen pozivni kod.",
        "demo_notice": "⏱ Ovaj demo nalog biće obrisan nakon {n} sata/i.",
        "domain": "Domen",
        "domain_ph": "primer.rs",
        "domain_notice": "Dodajte svoj domen u kontrolnom panelu nakon registracije.",
        "to_panel": "Na panel",
        "invite_required": "Pozivni kod je potreban za registraciju.",
        "cookie_banner_text": "Koristimo neophodne kolačiće za bezbednost (CSRF, sesija). Nastavkom pristajete na našu upotrebu kolačića.",
        "cookie_banner_btn": "Prihvati i nastavi",
        "cookie_banner_label": "Pristanak na kolačiće",
        "a11y_widget_label": "Alati za pristupačnost",
        "a11y_panel_label": "Opcije pristupačnosti",
        "a11y_title": "Pristupačnost",
        "a11y_font_size": "Veličina fonta",
        "a11y_font_dec": "Smanji veličinu fonta",
        "a11y_font_inc": "Povećaj veličinu fonta",
        "a11y_high_contrast": "Visoki kontrast",
        "a11y_grayscale": "Nivoi sive",
        "a11y_reduce_motion": "Smanji pokrete",
        "a11y_toggle_btn": "Otvori alate za pristupačnost"
      },
      "tr": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoNTEydjUxMkgweiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0yMDggMTE1YTE0MSAxNDEgMCAxIDAgMTA2IDI0MnEtMjUgMTMtNTQgMTNhMTE0IDExNCAwIDEgMSA1NC0yMTUgMTQxIDE0MSAwIDAgMC0xMDYtNDBtMTQyIDY3djU2bC01NCAxOCA1NCAxN3Y1N2wzMy00NiA1NCAxOC0zMy00NiAzMy00Ni01NCAxOHoiLz48L2c+PC9zdmc+",
        "name": "Türkçe",
        "subtitle": "kontrol paneli",
        "username": "Kullanıcı Adı",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "E-posta Adresi",
        "email_ph": "user@example.com",
        "password": "Şifre",
        "password_ph": "Min. 8 chars",
        "confirm": "Onayla",
        "confirm_ph": "Repeat",
        "register": "Giriş Yap",
        "already_registered": "Zaten kayıtlı mısınız?",
        "to_login": "Giriş Yap",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Zayıf",
        "pw_medium": "Orta",
        "pw_strong": "Güçlü",
        "please_wait": "Lütfen bekleyin...",
        "success_heading": "Hesap Oluşturuldu!",
        "generate": "Oluştur",
        "maintenance_heading": "Bakım Modu",
        "maintenance_text": "Yeni kayıtlar geçici olarak duraklatıldı.",
        "tos_prefix": "Kabul ediyorum",
        "tos_link": "Hizmet Şartları",
        "tos_and": "ve",
        "privacy_link": "Gizlilik Politikası",
        "did_you_mean": "Bunu mu demek istediniz",
        "setup_2fa": "İki Faktörlü Kimlik Doğrulamayı (2FA) etkinleştirmenizi öneririz.",
        "copy_pw": "Kopyala",
        "need_help": "Yardıma mı ihtiyacınız var?",
        "contact_support": "Destek ile İletişime Geç",
        "forgot_password": "Şifrenizi mi unuttunuz?",
        "pw_req_length": "En az {n}karakter",
        "pw_req_upper": "Bir büyük harf (A-Z)",
        "pw_req_lower": "Bir küçük harf (a-z)",
        "pw_req_number": "Bir rakam (0-9)",
        "email_mx_invalid": "E-posta alanı mesaj kabul etmiyor gibi görünüyor.",
        "pw_hibp_warning": "⚠️ Bu şifre {n} veri ihlalinde bulundu.",
        "pw_hibp_ok": "✓ Şifre bilinen sızıntılarda bulunmadı.",
        "pw_hibp_checking": "Şifre güvenliği kontrol ediliyor...",
        "invite_code": "Davet Kodu",
        "invite_code_ph": "Davet kodunuzu girin",
        "invite_invalid": "Geçersiz veya zaten kullanılmış davet kodu.",
        "demo_notice": "⏱ Bu demo hesap {n} saat sonra silinecektir.",
        "domain": "Alan Adı",
        "domain_ph": "ornek.com",
        "domain_notice": "Kayıt olduktan sonra alan adınızı kontrol panelinden ekleyin.",
        "to_panel": "Panele Git",
        "invite_required": "Kayıt olmak için davet kodu gereklidir.",
        "cookie_banner_text": "Güvenlik için (CSRF, oturum) gerekli çerezleri kullanıyoruz. Devam ederek çerez kullanımımızı kabul etmiş olursunuz.",
        "cookie_banner_btn": "Kabul Et ve Devam Et",
        "cookie_banner_label": "Çerez onayı",
        "a11y_widget_label": "Erişilebilirlik araçları",
        "a11y_panel_label": "Erişilebilirlik seçenekleri",
        "a11y_title": "Erişilebilirlik",
        "a11y_font_size": "Yazı Tipi Boyutu",
        "a11y_font_dec": "Yazı tipini küçült",
        "a11y_font_inc": "Yazı tipini büyüt",
        "a11y_high_contrast": "Yüksek Kontrast",
        "a11y_grayscale": "Gri Tonlama",
        "a11y_reduce_motion": "Hareketi Azalt",
        "a11y_toggle_btn": "Erişilebilirlik araçlarını aç"
        ,
        "cookie_text": "Bu web sitesi, en iyi deneyimi yaşamanızı sağlamak için çerezleri kullanır.",
        "cookie_btn": "Anladım!",
        "acc_title": "Erişilebilirlik",
        "acc_font": "Yazı Tipi Boyutu",
        "acc_contrast": "Yüksek Kontrast",
        "acc_grayscale": "Gri Tonlama",
        "acc_motion": "Hareketi Azalt",
        "need_help": "Yardıma mı ihtiyacınız var?"
      },
      "uk": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0wIDI1NiAyNTgtMzkuNEw1MTIgMjU2djI1NkgweiIvPjxwYXRoIGZpbGw9IiMzMzhhZjMiIGQ9Ik0wIDBoNTEydjI1NkgweiIvPjwvZz48L3N2Zz4=",
        "name": "Українська",
        "subtitle": "веб-панель керування",
        "username": "Ім'я користувача",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Адреса електронної пошти",
        "email_ph": "user@example.com",
        "password": "Пароль",
        "password_ph": "Min. 8 chars",
        "confirm": "Підтвердити",
        "confirm_ph": "Repeat",
        "register": "Увійти",
        "already_registered": "Вже зареєстровані?",
        "to_login": "Увійти",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Слабкий",
        "pw_medium": "Середній",
        "pw_strong": "Надійний",
        "please_wait": "Будь ласка, зачекайте...",
        "success_heading": "Акаунт створено!",
        "generate": "Згенерувати",
        "maintenance_heading": "Режим обслуговування",
        "maintenance_text": "Нові реєстрації тимчасово призупинено.",
        "tos_prefix": "Я погоджуюсь з",
        "tos_link": "Умовами використання",
        "tos_and": "та",
        "privacy_link": "Політикою конфіденційності",
        "did_you_mean": "Можливо, ви мали на увазі",
        "setup_2fa": "Ми рекомендуємо увімкнути двофакторну автентифікацію (2FA).",
        "copy_pw": "Копіювати",
        "need_help": "Потрібна допомога?",
        "contact_support": "Зв'язатися з підтримкою",
        "forgot_password": "Забули пароль?",
        "pw_req_length": "Принаймні {n}символів",
        "pw_req_upper": "Одна велика літера (A-Z)",
        "pw_req_lower": "Одна мала літера (a-z)",
        "pw_req_number": "Одна цифра (0-9)",
        "email_mx_invalid": "Схоже, що домен пошти не приймає повідомлення.",
        "pw_hibp_warning": "⚠️ Цей пароль з'являвся у {n} витоках даних.",
        "pw_hibp_ok": "✓ Пароль не знайдено у відомих витоках.",
        "pw_hibp_checking": "Перевірка безпеки пароля...",
        "invite_code": "Код запрошення",
        "invite_code_ph": "Введіть код запрошення",
        "invite_invalid": "Недійсний або вже використаний код запрошення.",
        "demo_notice": "⏱ Це демо-акаунт, і його буде видалено через {n} год.",
        "domain": "Домен",
        "domain_ph": "example.com",
        "domain_notice": "Додайте свій домен у панелі керування після реєстрації.",
        "to_panel": "До панелі",
        "invite_required": "Для реєстрації потрібен код запрошення.",
        "cookie_banner_text": "Ми використовуємо необхідні файли cookie для безпеки (CSRF, сесія). Продовжуючи, ви погоджуєтеся з використанням cookie.",
        "cookie_banner_btn": "Прийняти та продовжити",
        "cookie_banner_label": "Згода на файли cookie",
        "a11y_widget_label": "Інструменти доступності",
        "a11y_panel_label": "Параметри доступності",
        "a11y_title": "Доступність",
        "a11y_font_size": "Розмір шрифту",
        "a11y_font_dec": "Зменшити розмір шрифту",
        "a11y_font_inc": "Збільшити розмір шрифту",
        "a11y_high_contrast": "Високий контраст",
        "a11y_grayscale": "Відтінки сірого",
        "a11y_reduce_motion": "Зменшити рух",
        "a11y_toggle_btn": "Відкрити інструменти доступності"
        ,
        "cookie_text": "Цей веб-сайт використовує файли cookie для забезпечення найкращого користувацького досвіду.",
        "cookie_btn": "Зрозуміло!",
        "acc_title": "Спеціальні можливості",
        "acc_font": "Розмір шрифту",
        "acc_contrast": "Високий контраст",
        "acc_grayscale": "Відтінки сірого",
        "acc_motion": "Зменшити рух",
        "need_help": "Потрібна допомога?"
      },
      "vi": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoNTEydjUxMkgwWiIvPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0xNzYgMzc4IDIwOC0xNTBIMTI4bDIwOCAxNTAtODAtMjQ0WiIvPjwvZz48L3N2Zz4=",
        "name": "Tiếng Việt",
        "subtitle": "bảng điều khiển",
        "username": "Tên người dùng",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "Địa chỉ Email",
        "email_ph": "user@example.com",
        "password": "Mật khẩu",
        "password_ph": "Min. 8 chars",
        "confirm": "Xác nhận",
        "confirm_ph": "Repeat",
        "register": "Đăng nhập",
        "already_registered": "Đã có tài khoản?",
        "to_login": "Đăng nhập",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Yếu",
        "pw_medium": "Trung bình",
        "pw_strong": "Mạnh",
        "please_wait": "Vui lòng đợi...",
        "success_heading": "Đã tạo tài khoản!",
        "generate": "Tạo ngẫu nhiên",
        "maintenance_heading": "Chế độ bảo trì",
        "maintenance_text": "Đăng ký mới tạm thời bị vô hiệu hóa.",
        "tos_prefix": "Tôi đồng ý với",
        "tos_link": "Điều khoản Dịch vụ",
        "tos_and": "và",
        "privacy_link": "Chính sách Bảo mật",
        "did_you_mean": "Ý bạn là",
        "setup_2fa": "Chúng tôi khuyên bạn nên bật Xác thực hai yếu tố (2FA).",
        "copy_pw": "Sao chép",
        "need_help": "Cần giúp đỡ?",
        "contact_support": "Liên hệ Hỗ trợ",
        "forgot_password": "Quên mật khẩu?",
        "pw_req_length": "Ít nhất {n}ký tự",
        "pw_req_upper": "Một chữ hoa (A-Z)",
        "pw_req_lower": "Một chữ thường (a-z)",
        "pw_req_number": "Một số (0-9)",
        "email_mx_invalid": "Tên miền email có vẻ không nhận được thư.",
        "pw_hibp_warning": "⚠️ Mật khẩu này đã xuất hiện trong {n} vụ rò rỉ dữ liệu.",
        "pw_hibp_ok": "✓ Mật khẩu không được tìm thấy trong các vụ rò rỉ.",
        "pw_hibp_checking": "Đang kiểm tra bảo mật mật khẩu...",
        "invite_code": "Mã mời",
        "invite_code_ph": "Nhập mã mời của bạn",
        "invite_invalid": "Mã mời không hợp lệ hoặc đã được sử dụng.",
        "demo_notice": "⏱ Đây là tài khoản demo và sẽ bị xóa sau {n} giờ.",
        "domain": "Tên miền",
        "domain_ph": "vd.com",
        "domain_notice": "Thêm tên miền của bạn trong bảng điều khiển sau khi đăng ký.",
        "to_panel": "Bảng điều khiển",
        "invite_required": "Cần có mã mời để đăng ký.",
        "cookie_banner_text": "Chúng tôi sử dụng cookie thiết yếu cho bảo mật (CSRF, phiên). Bằng cách tiếp tục, bạn đồng ý với việc sử dụng cookie.",
        "cookie_banner_btn": "Chấp nhận & Tiếp tục",
        "cookie_banner_label": "Chấp thuận cookie",
        "a11y_widget_label": "Công cụ trợ năng",
        "a11y_panel_label": "Tùy chọn trợ năng",
        "a11y_title": "Trợ năng",
        "a11y_font_size": "Cỡ chữ",
        "a11y_font_dec": "Giảm cỡ chữ",
        "a11y_font_inc": "Tăng cỡ chữ",
        "a11y_high_contrast": "Độ tương phản cao",
        "a11y_grayscale": "Thang độ xám",
        "a11y_reduce_motion": "Giảm chuyển động",
        "a11y_toggle_btn": "Mở công cụ trợ năng"
        ,
        "cookie_text": "Trang web này sử dụng cookie để đảm bảo bạn có được trải nghiệm tốt nhất.",
        "cookie_btn": "Đã hiểu!",
        "acc_title": "Trợ năng",
        "acc_font": "Cỡ chữ",
        "acc_contrast": "Độ tương phản cao",
        "acc_grayscale": "Thang độ xám",
        "acc_motion": "Giảm chuyển động",
        "need_help": "Cần giúp đỡ?"
      },
      "zh": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoNTEydjUxMkgweiIvPjxwYXRoIGZpbGw9IiNmZmRhNDQiIGQ9Im0xNDAuMSAxNTUuOCAyMi4xIDY4aDcxLjVsLTU3LjggNDIuMSAyMi4xIDY4LTU3LjktNDItNTcuOSA0MiAyMi4yLTY4LTU3LjktNDIuMUgxMTh6bTE2My40IDI0MC43LTE2LjktMjAuOC0yNSA5LjcgMTQuNS0yMi41LTE2LjktMjAuOSAyNS45IDYuOSAxNC42LTIyLjUgMS40IDI2LjggMjYgNi45LTI1LjEgOS42em0zMy42LTYxIDgtMjUuNi0yMS45LTE1LjUgMjYuOC0uNCA3LjktMjUuNiA4LjcgMjUuNCAyNi44LS4zLTIxLjUgMTYgOC42IDI1LjQtMjEuOS0xNS41em00NS4zLTE0Ny42TDM3MC42IDIxMmwxOS4yIDE4LjctMjYuNS0zLjgtMTEuOCAyNC00LjYtMjYuNC0yNi42LTMuOCAyMy44LTEyLjUtNC42LTI2LjUgMTkuMiAxOC43em0tNzguMi03My0yIDI2LjcgMjQuOSAxMC4xLTI2LjEgNi40LTEuOSAyNi44LTE0LjEtMjIuOC0yNi4xIDYuNCAxNy4zLTIwLjUtMTQuMi0yMi43IDI0LjkgMTAuMXoiLz48L2c+PC9zdmc+",
        "name": "中文",
        "subtitle": "控制面板",
        "username": "用户名",
        "username_ph": "4–8 chars, a-z 0-9",
        "email": "电子邮件地址",
        "email_ph": "user@example.com",
        "password": "密码",
        "password_ph": "Min. 8 chars",
        "confirm": "确认",
        "confirm_ph": "Repeat",
        "register": "登录",
        "already_registered": "已经注册了吗？",
        "to_login": "去登录",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "弱",
        "pw_medium": "中",
        "pw_strong": "强",
        "please_wait": "请稍候...",
        "success_heading": "帐户已创建！",
        "generate": "生成",
        "maintenance_heading": "维护模式",
        "maintenance_text": "新注册暂时停止。",
        "tos_prefix": "我同意",
        "tos_link": "服务条款",
        "tos_and": "和",
        "privacy_link": "隐私政策",
        "did_you_mean": "你的意思是",
        "setup_2fa": "我们建议在面板中启用双因素身份验证 (2FA)。",
        "copy_pw": "复制",
        "need_help": "需要帮助吗？",
        "contact_support": "联系支持",
        "forgot_password": "忘记密码？",
        "pw_req_length": "至少 {n} 个字符",
        "pw_req_upper": "一个大写字母 (A-Z)",
        "pw_req_lower": "一个小写字母 (a-z)",
        "pw_req_number": "一个数字 (0-9)",
        "email_mx_invalid": "该电子邮件域似乎不接受邮件。",
        "pw_hibp_warning": "⚠️ 该密码已出现在 {n} 次数据泄露中。",
        "pw_hibp_ok": "✓ 未在已知数据泄露中找到密码。",
        "pw_hibp_checking": "正在检查密码安全性...",
        "invite_code": "邀请码",
        "invite_code_ph": "Enter your invite code",
        "invite_invalid": "邀请码无效或已被使用。",
        "demo_notice": "⏱ 这是一个演示帐户，将在 {n} 小时后被自动删除。",
        "cookie_banner_text": "我们出于安全目的（CSRF、会话）使用必要的 Cookie。继续操作即表示您同意我们使用 Cookie。",
        "cookie_banner_btn": "接受并继续",
        "cookie_banner_label": "Cookie 同意",
        "a11y_widget_label": "无障碍工具",
        "a11y_panel_label": "无障碍选项",
        "a11y_title": "无障碍",
        "a11y_font_size": "字号大小",
        "a11y_font_dec": "减小字号",
        "a11y_font_inc": "增大字号",
        "a11y_high_contrast": "高对比度",
        "a11y_grayscale": "灰度模式",
        "a11y_reduce_motion": "减少动画",
        "a11y_toggle_btn": "打开无障碍工具",
        "domain": "Domain",
        "domain_ph": "example.com",
        "domain_notice": "注册后在控制面板中添加您的域名。",
        "to_panel": "To Panel",
        "invite_required": "An invitation code is required to register."
        ,
        "cookie_text": "本网站使用 cookie 以确保您获得最佳体验。",
        "cookie_btn": "知道了！",
        "acc_title": "辅助功能",
        "acc_font": "字体大小",
        "acc_contrast": "高对比度",
        "acc_grayscale": "灰度",
        "acc_motion": "减少运动",
        "need_help": "需要帮助吗？"
      },
      "ar": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiM0OTZlMmQiIGQ9Ik0wIDBoNTEydjUxMkgwWiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0zMzYgMzU2djE2SDEyOGwyNCAyNGgxODR2MTZoMTZ2LTE2aDMydi0yNGgtMzJ2LTE2ek0xMzEuNCAxNzR2NDEuNGgtMTUuOHYtMjYuN0g5Ny44cS02LjMgMC0xMC44IDIuM2ExNSAxNSAwIDAgMC02LjcgNi40IDIyIDIyIDAgMCAwLTIuMyAxMC41cTAgNiAyLjMgMTAuMyAyLjMgNCA2LjcgNiA0LjUgMi4xIDEwLjggMi4xSDE3M1YxNzRoLTEzdjQxLjRoLTE1LjhWMTc0em01Mi45IDB2NTIuM2gxMi44VjE3NHptNTUuMyAwdjQxLjRoLTExdi0zMWgtMTIuOHYzMWgtOS4zdjEwLjloNDUuOVYxNzR6bTI0LjMgMHY1Mi4zaDEyLjhWMTc0em03Ny44IDB2NDEuNEgzMjZ2LTI2LjdoLTE3LjhxLTYuMyAwLTEwLjggMi4zYTE1IDE1IDAgMCAwLTYuNyA2LjQgMjIgMjIgMCAwIDAtMi4zIDEwLjVxMCA2IDIuMyAxMC4zIDIuMyA0IDYuNyA2IDQuNSAyLjEgMTAuOCAyLjFoNDYuNVYxNzR6bTI0LjIgMHY1Mi4zaDEyLjhWMTc0em01NS4zIDB2NDEuNGgtMTF2LTMxaC0xMi44djMxaC05LjN2MTAuOWg0NlYxNzRaTTk3LjggMTk5LjZoNXYxNS44aC01cS0yLjQgMC00LS40LTEuNS0uNS0yLjItMmExMyAxMyAwIDAgMS0uOC01LjFxMC0zLjcuOC01LjQgMS0xLjggMi41LTIuMyAxLjUtLjYgMy43LS42bTIxMC4zIDBoNXYxNS44aC01cS0yLjQgMC00LS40LTEuNS0uNS0yLjItMmExMyAxMyAwIDAgMS0uOC01LjFxMC0zLjcuOC01LjQgMS0xLjggMi41LTIuMyAxLjYtLjYgMy43LS42TTExNC44IDI0N3YyOC41aC0xMC45VjI1N0g5MS42cS00LjQgMC03LjQgMS42LTMgMS40LTQuNiA0LjR0LTEuNiA3LjJxMCA0LjMgMS42IDcgMS41IDIuOSA0LjYgNC4zdDcuNCAxLjRoNTEuN3YtMzZoLTguOHYyOC41aC0xMC45VjI0N1ptMzYuMyAwdjM2aDguOHYtMzZabTM5LjcgMHYzNS44cTAgMS41LS42IDIuN3QtMiAycS0xLjUuNi00IC43dC00LjItLjctMi40LTJxLS45LTEuMy0uOS0zLjFsLjItMi44IDEuNS0xMC44LTguNy0xLjEtMS4yIDguNC0uNiA2LjRxMCAzLjcgMiA2LjdhMTQgMTQgMCAwIDAgNS45IDQuOHEzLjYgMS43IDguMyAxLjcgNC41IDAgOC0xLjYgMy42LTEuNiA1LjUtNC42IDItMi44IDItNi43VjI0N1ptMTU5LjUgMTBhMzYgMzYgMCAwIDAtMTAgMS40IDQwIDQwIDAgMCAwLTEuMyA3LjQgNTcgNTcgMCAwIDAgMCA5LjZoLTExdi0yYTIwIDIwIDAgMCAwLTEuOS05LjJxLTEuOC0zLjYtNS40LTUuM2EyMCAyMCAwIDAgMC04LjctMS44aC00LjJ2Ny41aDQuMnEyLjcgMCA0LjMuOCAxLjUuNyAyLjIgMi42LjYgMS44LjcgNS40djJoLTEyLjd2Ny42SDQzNHYtMTIuOHEwLTUtMS42LTcuOC0xLjUtMy00LjctNC4xLTMuMi0xLjQtOC0xLjNhMzYgMzYgMCAwIDAtMTAgMS40IDQwIDQwIDAgMCAwLTEuNCA3LjQgNTcgNTcgMCAwIDAgMCA5LjZoLTEwLjl2LTQuOHEwLTQuMi0yLTcuMnQtNS41LTQuNmExOCAxOCAwIDAgMC03LjktMS43cS0yLjEgMC00LjIuNGwtNC4zLjguNyA3YTQ4IDQ4IDAgMCAxIDYuNy0uNnE0IDAgNiAxLjUgMS43IDEuNSAxLjcgNC40djQuOWgtMjMuOXYtNS4zcTAtNS0xLjYtNy44LTEuNi0zLTQuOC00LjEtMy0xLjQtOC0xLjNtLTEzMS43LjFxLTQuMyAwLTcuNCAxLjYtMyAxLjQtNC42IDQuNHQtMS42IDcuMnEwIDQuMyAxLjYgNyAxLjYgMi45IDQuNiA0LjN0Ny40IDEuNGgzLjV2MS42cTAgMi4zLTEuNSAzLjQtMS40IDEuMi00LjcgMS4ybC0zLS4ycS0xLjggMC00LjMtLjRsLTEuMiA3YTU5IDU5IDAgMCAwIDguNSAxcTQuNSAwIDcuOC0xLjQgMy40LTEuNSA1LjMtNC4yYTExIDExIDAgMCAwIDEuOS02LjRWMjgzaDIyLjlhMTUgMTUgMCAwIDAgNy45LTJxMSAuNiAyLjIgMSAyLjMgMSA0LjcgMWgxMy45di0xNGwtLjMtMy4zLTEuMy04LjYtOC43IDEuM2ExMTggMTE4IDAgMCAxIDEuNCAxMC41djYuNmgtNWwtMS45LS40LS45LS41cS43LTIuNy43LTYuMnYtOC42aC04Ljh2OC42cTAgMy0uNCA0LjYtLjMgMS41LTEgMmE1IDUgMCAwIDEtMi41LjVoLTN2LTEzaC05djEzSDIzMVYyNTd6bTczLjggMHYyNi42cTAgMi43LTEgNC0xIDEuNS0yLjggMS41aC0yLjhsLS4yIDcuMyAzLjEuMnEzLjggMCA2LjYtMS43dDQuMy00LjYgMS42LTYuN1YyNTd6bTU4IDcuNHEyLjEgMCAzLjMuNXQxLjcgMS43cS40IDEuMy40IDMuNHY1LjRoLThhNzEgNzEgMCAwIDEgMC04LjZsLjItMi4zem02OS4zIDBxMi4yIDAgMy40LjV0MS42IDEuN3EuNSAxLjMuNSAzLjR2NS40aC04YTcxIDcxIDAgMCAxLS4xLTguNmwuMi0yLjN6bS0zMjguMS4xSDk1djEwLjloLTMuNHEtMS43IDAtMi43LS4zLTEtLjQtMS42LTEuNGE5IDkgMCAwIDEtLjUtMy41cTAtMi42LjYtMy43QTMgMyAwIDAgMSA4OSAyNjVhOCA4IDAgMCAxIDIuNS0uNG0xMjcgMGgzLjV2MTAuOWgtMy41cS0xLjYgMC0yLjctLjMtMS0uNC0xLjYtMS40YTkgOSAwIDAgMS0uNS0zLjVxMC0yLjYuNi0zLjdhMyAzIDAgMCAxIDEuNy0xLjYgOCA4IDAgMCAxIDIuNS0uNCIvPjwvZz48L3N2Zz4=",
        "rtl": true,
        "name": "العربية",
        "subtitle": "لوحة تحكم الويب",
        "username": "اسم المستخدم",
        "username_ph": "4–8 أحرف، a-z 0-9",
        "email": "البريد الإلكتروني",
        "email_ph": "user@example.com",
        "domain": "النطاق",
        "domain_ph": "example.com",
        "domain_notice": "أضف نطاقك في لوحة التحكم بعد التسجيل.",
        "password": "كلمة المرور",
        "password_ph": "8 أحرف على الأقل",
        "confirm": "تأكيد كلمة المرور",
        "confirm_ph": "إعادة الإدخال",
        "register": "تسجيل",
        "already_registered": "هل لديك حساب بالفعل؟",
        "to_login": "تسجيل الدخول",
        "to_panel": "الانتقال إلى اللوحة",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "ضعيفة",
        "pw_medium": "متوسطة",
        "pw_strong": "قوية",
        "please_wait": "يرجى الانتظار...",
        "success_heading": "تم إنشاء الحساب!",
        "generate": "توليد",
        "maintenance_heading": "وضع الصيانة",
        "maintenance_text": "التسجيلات الجديدة متوقفة حاليًا للصيانة. يرجى التحقق لاحقًا.",
        "tos_prefix": "أوافق على",
        "tos_link": "شروط الخدمة",
        "tos_and": "و",
        "privacy_link": "سياسة الخصوصية",
        "did_you_mean": "هل تقصد",
        "setup_2fa": "نوصي بتمكين المصادقة الثنائية (2FA) في اللوحة.",
        "copy_pw": "نسخ",
        "need_help": "هل تحتاج مساعدة؟",
        "contact_support": "الاتصال بالدعم",
        "forgot_password": "نسيت كلمة المرور؟",
        "pw_req_length": "{n} أحرف على الأقل",
        "pw_req_upper": "حرف كبير واحد (A-Z)",
        "pw_req_lower": "حرف صغير واحد (a-z)",
        "pw_req_number": "رقم واحد (0-9)",
        "email_mx_invalid": "يبدو أن نطاق البريد لا يقبل الرسائل.",
        "pw_hibp_warning": "⚠️ ظهرت كلمة المرور هذه في {n} تسريب(ات) للبيانات.",
        "pw_hibp_ok": "✓ لم يتم العثور على كلمة المرور في التسريبات المعروفة.",
        "pw_hibp_checking": "جاري التحقق من أمان كلمة المرور...",
        "invite_code": "رمز الدعوة",
        "invite_code_ph": "أدخل رمز الدعوة",
        "invite_required": "رمز الدعوة مطلوب للتسجيل.",
        "invite_invalid": "رمز دعوة غير صالحة أو مستخدمة بالفعل.",
        "cookie_banner_text": "نستخدم الكوكيز الأساسية للأمان (CSRF، الجلسة). بالمتابعة، فإنك توافق على استخدامنا للكوكيز.",
        "cookie_banner_btn": "قبول ومتابعة",
        "cookie_banner_label": "الموافقة على الكوكيز",
        "a11y_widget_label": "أدوات إمكانية الوصول",
        "a11y_panel_label": "خيارات إمكانية الوصول",
        "a11y_title": "إمكانية الوصول",
        "a11y_font_size": "حجم الخط",
        "a11y_font_dec": "تصغير الخط",
        "a11y_font_inc": "تكبير الخط",
        "a11y_high_contrast": "تباين عالٍ",
        "a11y_grayscale": "تدرج رمادي",
        "a11y_reduce_motion": "تقليل الحركة",
        "a11y_toggle_btn": "فتح أدوات إمكانية الوصول"
        ,
        "cookie_text": "يستخدم هذا الموقع ملفات تعريف الارتباط لضمان حصولك على أفضل تجربة.",
        "cookie_btn": "فهمت ذلك!",
        "acc_title": "إمكانية الوصول",
        "acc_font": "حجم الخط",
        "acc_contrast": "تباين عالي",
        "acc_grayscale": "تدرج رمادي",
        "acc_motion": "تقليل الحركة",
        "need_help": "تحتاج مساعدة؟"
      },
      "ru": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiMwMDUyYjQiIGQ9Ik01MTIgMTcwdjE3MmwtMjU2IDMyTDAgMzQyVjE3MGwyNTYtMzJ6Ii8+PHBhdGggZmlsbD0iI2VlZSIgZD0iTTUxMiAwdjE3MEgwVjBaIi8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0iTTUxMiAzNDJ2MTcwSDBWMzQyWiIvPjwvZz48L3N2Zz4=",
        "name": "Русский",
        "subtitle": "панель управления web",
        "username": "Имя пользователя",
        "username_ph": "4–8 симв., a-z 0-9",
        "email": "Электронная почта",
        "email_ph": "user@example.com",
        "domain": "Домен",
        "domain_ph": "example.com",
        "domain_notice": "Добавьте свой домен в панели управления после регистрации.",
        "password": "Пароль",
        "password_ph": "Мин. 8 симв.",
        "confirm": "Подтверждение",
        "confirm_ph": "Повторите",
        "register": "Зарегистрироваться",
        "already_registered": "Уже зарегистрированы?",
        "to_login": "Войти",
        "to_panel": "В панель",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Слабый",
        "pw_medium": "Средний",
        "pw_strong": "Надежный",
        "please_wait": "Пожалуйста, подождите...",
        "success_heading": "Аккаунт создан!",
        "generate": "Сгенерировать",
        "maintenance_heading": "Режим обслуживания",
        "maintenance_text": "Новые регистрации временно приостановлены для проведения технических работ. Пожалуйста, зайдите позже.",
        "tos_prefix": "Я согласен с",
        "tos_link": "Условиями обслуживания",
        "tos_and": "и",
        "privacy_link": "Политикой конфиденциальности",
        "did_you_mean": "Возможно, вы имели в виду",
        "setup_2fa": "Мы рекомендуем включить двухфакторную аутентификацию (2FA) в панели.",
        "copy_pw": "Копировать",
        "need_help": "Нужна помощь?",
        "contact_support": "Связаться с поддержкой",
        "forgot_password": "Забыли пароль?",
        "pw_req_length": "Мин. {n} символов",
        "pw_req_upper": "Одна заглавная буква (A-Z)",
        "pw_req_lower": "Одна строчная буква (a-z)",
        "pw_req_number": "Одна цифра (0-9)",
        "email_mx_invalid": "Похоже, почтовый домен не принимает почту.",
        "pw_hibp_warning": "⚠️ Этот пароль был найден в {n} утечках данных.",
        "pw_hibp_ok": "✓ Пароль не найден в известных утечках данных.",
        "pw_hibp_checking": "Проверка безопасности пароля...",
        "invite_code": "Код приглашения",
        "invite_code_ph": "Введите код приглашения",
        "invite_required": "Для регистрации требуется код приглашения.",
        "invite_invalid": "Недействительный или уже использованный код приглашения.",
        "cookie_banner_text": "Мы используем необходимые файлы cookie для безопасности (CSRF, сессия). Продолжая, вы соглашаетесь с использованием cookie.",
        "cookie_banner_btn": "Принять и продолжить",
        "cookie_banner_label": "Согласие на куки",
        "a11y_widget_label": "Инструменты доступности",
        "a11y_panel_label": "Параметры доступности",
        "a11y_title": "Доступность",
        "a11y_font_size": "Размер шрифта",
        "a11y_font_dec": "Уменьшить шрифт",
        "a11y_font_inc": "Увеличить шрифт",
        "a11y_high_contrast": "Высокий контраст",
        "a11y_grayscale": "Оттенки серого",
        "a11y_reduce_motion": "Уменьшение движения",
        "a11y_toggle_btn": "Открыть инструменты доступности"
        ,
        "cookie_text": "Этот сайт использует файлы cookie для обеспечения лучшего пользовательского опыта.",
        "cookie_btn": "Понятно!",
        "acc_title": "Специальные возможности",
        "acc_font": "Размер шрифта",
        "acc_contrast": "Высокий контраст",
        "acc_grayscale": "Оттенки серого",
        "acc_motion": "Уменьшить движение",
        "need_help": "Нужна помощь?"
      },
      "sr": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiMwMDUyYjQiIGQ9Im0wIDE2NyAyNTMuOC0xOS4zTDUxMiAxNjd2MTc4bC0yNTQuOSAzMi4zTDAgMzQ1eiIvPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoNTEydjE2N0gweiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0wIDM0NWg1MTJ2MTY3SDB6Ii8+PHBhdGggZmlsbD0iI2Q4MDAyNyIgZD0iTTY2LjIgMTQ0Ljd2MTI3LjdjMCA3Mi42IDk0LjkgOTUgOTQuOSA5NXM5NC45LTIyLjQgOTQuOS05NVYxNDQuN3oiLz48cGF0aCBmaWxsPSIjZmZkYTQ0IiBkPSJNMTA1LjQgMTY3aDExMS40di00NC42bC0yMi4zIDExLjItMzMuNC0zMy40LTMzLjQgMzMuNC0yMi4zLTExLjJ6bTEyOC4zIDEyMy4yLTcyLjMtNzIuNEw4OSAyOTAuMmwyMy43IDIzLjYgNDguNy00OC43IDQ4LjcgNDguN3oiLz48cGF0aCBmaWxsPSIjZWVlIiBkPSJNMjMzLjcgMjIyLjZIMjAwYTIyLjEgMjIuMSAwIDAgMCAzLTExLjEgMjIuMyAyMi4zIDAgMCAwLTQyLTEwLjUgMjIuMyAyMi4zIDAgMCAwLTQxLjkgMTAuNSAyMi4xIDIyLjEgMCAwIDAgMyAxMS4xSDg5YTIzIDIzIDAgMCAwIDIzIDIyLjNoLS43YzAgMTIuMyAxMCAyMi4yIDIyLjMgMjIuMiAwIDExIDcuOCAyMCAxOC4xIDIxLjlsLTE3LjUgMzkuNmE3Mi4xIDcyLjEgMCAwIDAgMjcuMiA1LjMgNzIuMSA3Mi4xIDAgMCAwIDI3LjItNS4zTDE3MS4xIDI4OWMxMC4zLTIgMTguMS0xMSAxOC4xLTIxLjkgMTIuMyAwIDIyLjMtMTAgMjIuMy0yMi4yaC0uOGEyMyAyMyAwIDAgMCAyMy0yMi4zeiIvPjwvZz48L3N2Zz4=",
        "name": "Српски (ћирилица)",
        "subtitle": "контролни панел",
        "username": "Корисничко име",
        "username_ph": "4–8 знакова, a-z 0-9",
        "email": "Е-пошта адреса",
        "email_ph": "user@example.com",
        "password": "Лозинка",
        "password_ph": "Мин. 8 знакова",
        "confirm": "Потврди",
        "confirm_ph": "Понови",
        "register": "Пријавите се",
        "already_registered": "Већ сте регистровани?",
        "to_login": "Пријавите се",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Слаба",
        "pw_medium": "Средња",
        "pw_strong": "Јака",
        "please_wait": "Сачекајте...",
        "success_heading": "Налог је креиран!",
        "generate": "Генериши",
        "maintenance_heading": "Режим одржавања",
        "maintenance_text": "Нове регистрације су привремено паузиране.",
        "tos_prefix": "Слажем се са",
        "tos_link": "Условима коришћења",
        "tos_and": "и",
        "privacy_link": "Политиком приватности",
        "did_you_mean": "Да ли сте мислили",
        "setup_2fa": "Препоручујемо да омогућите двофакторску аутентификацију (2FA).",
        "copy_pw": "Копирај",
        "need_help": "Треба вам помоћ?",
        "contact_support": "Контактирајте подршку",
        "forgot_password": "Заборавили сте лозинку?",
        "pw_req_length": "Најмање {n} карактера",
        "pw_req_upper": "Једно велико слово (A-Z)",
        "pw_req_lower": "Једно мало слово (a-z)",
        "pw_req_number": "Један број (0-9)",
        "email_mx_invalid": "Е-пошта домен не прихвата поруке.",
        "pw_hibp_warning": "⚠️ Ова лозинка се појавила у {n} цурења података.",
        "pw_hibp_ok": "✓ Лозинка није пронађена у познатим цурењима.",
        "pw_hibp_checking": "Провера безбедности лозинке...",
        "invite_code": "Позивни код",
        "invite_code_ph": "Унесите позивни код",
        "invite_invalid": "Неважећи или већ искоришћен позивни код.",
        "demo_notice": "⏱ Овај демо налог биће обрисан након {n} сата/и.",
        "domain": "Домен",
        "domain_ph": "primer.rs",
        "domain_notice": "Додајте свој домен у контролном панелу након регистрације.",
        "to_panel": "На панел",
        "invite_required": "Позивни код је потребан за регистрацију.",
        "cookie_banner_text": "Користимо неопходне колачиће за безбедност (CSRF, сесија). Наставком пристајете на нашу употребу колачића.",
        "cookie_banner_btn": "Прихвати и настави",
        "cookie_banner_label": "Пристанак на колачиће",
        "a11y_widget_label": "Алати за приступачност",
        "a11y_panel_label": "Опције приступачности",
        "a11y_title": "Приступачност",
        "a11y_font_size": "Величинa фонта",
        "a11y_font_dec": "Смањи величину фонта",
        "a11y_font_inc": "Повећај величину фонта",
        "a11y_high_contrast": "Високи контраст",
        "a11y_grayscale": "Нивои сиве",
        "a11y_reduce_motion": "Смањи покрете",
        "a11y_toggle_btn": "Отвори алате за приступачност"
      },
      "nb": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNkODAwMjciIGQ9Ik0wIDBoMTAwLjJsNjYuMSA1My41TDIzMy43IDBINTEydjE4OS4zTDQ2Ni4zIDI1N2w0NS43IDY1LjhWNTEySDIzMy43bC02OC01MC43LTY1LjUgNTAuN0gwVjMyMi44bDUxLjQtNjguNS01MS40LTY1eiIvPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0xMDAuMiAwdjE4OS4zSDB2MzMuNGwyNC42IDMzTDAgMjg5LjV2MzMuNGgxMDAuMlY1MTJoMzMuNGwzMC42LTI2LjMgMzYuMSAyNi4zaDMzLjRWMzIyLjhINTEydi0zMy40bC0yNC42LTMzLjcgMjQuNi0zM3YtMzMuNEgyMzMuN1YwaC0zMy40bC0zMy44IDI1LjNMMTMzLjYgMHoiLz48cGF0aCBmaWxsPSIjMDA1MmI0IiBkPSJNMTMzLjYgMHYyMjIuN0gwdjY2LjdoMTMzLjZWNTEyaDY2LjdWMjg5LjRINTEydi02Ni43SDIwMC4zVjB6Ii8+PC9nPjwvc3ZnPg==",
        "name": "Norsk bokmål",
        "subtitle": "kontrollpanel",
        "username": "Brukernavn",
        "username_ph": "4–8 tegn, a-z 0-9",
        "email": "E-postadresse",
        "email_ph": "bruker@eksempel.no",
        "password": "Passord",
        "password_ph": "Minst 8 tegn",
        "confirm": "Bekreft",
        "confirm_ph": "Gjenta",
        "register": "Logg inn",
        "already_registered": "Allerede registrert?",
        "to_login": "Til innlogging",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "Svakt",
        "pw_medium": "Middels",
        "pw_strong": "Sterkt",
        "please_wait": "Vennligst vent...",
        "success_heading": "Konto opprettet!",
        "generate": "Generer",
        "maintenance_heading": "Vedlikeholdsmodus",
        "maintenance_text": "Nye registreringer er midlertidig stoppet.",
        "tos_prefix": "Jeg godtar",
        "tos_link": "Vilkårene for bruk",
        "tos_and": "og",
        "privacy_link": "Personvernerklæringen",
        "did_you_mean": "Mente du",
        "setup_2fa": "Vi anbefaler å aktivere tofaktorautentisering (2FA).",
        "copy_pw": "Kopier",
        "need_help": "Trenger du hjelp?",
        "contact_support": "Kontakt brukerstøtte",
        "forgot_password": "Glemt passord?",
        "pw_req_length": "Minst {n} tegn",
        "pw_req_upper": "Én stor bokstav (A-Z)",
        "pw_req_lower": "Én liten bokstav (a-z)",
        "pw_req_number": "Ett tall (0-9)",
        "email_mx_invalid": "E-postdomenet ser ikke ut til å ta imot e-post.",
        "pw_hibp_warning": "⚠️ Dette passordet er funnet i {n} datalekkasje(r).",
        "pw_hibp_ok": "✓ Passordet er ikke funnet i kjente datalekkasjer.",
        "pw_hibp_checking": "Sjekker passordsikkerhet...",
        "invite_code": "Invitasjonskode",
        "invite_code_ph": "Skriv inn invitasjonskode",
        "invite_invalid": "Ugyldig eller allerede brukt invitasjonskode.",
        "demo_notice": "⏱ Dette er en demokonto og slettes etter {n} time(r).",
        "domain": "Domene",
        "domain_ph": "eksempel.no",
        "domain_notice": "Legg til domenet ditt i kontrollpanelet etter registrering.",
        "to_panel": "Til panelet",
        "invite_required": "En invitasjonskode kreves for å registrere seg.",
        "cookie_banner_text": "Vi bruker nødvendige informasjonskapsler for sikkerhet (CSRF, økt). Ved å fortsette godtar du vår bruk av informasjonskapsler.",
        "cookie_banner_btn": "Godta og fortsett",
        "cookie_banner_label": "Samtykke til informasjonskapsler",
        "a11y_widget_label": "Tilgjengelighetsverktøy",
        "a11y_panel_label": "Tilgjengelighetsvalg",
        "a11y_title": "Tilgjengelighet",
        "a11y_font_size": "Skriftstørrelse",
        "a11y_font_dec": "Minsk skriftstørrelse",
        "a11y_font_inc": "Øk skriftstørrelse",
        "a11y_high_contrast": "Høy kontrast",
        "a11y_grayscale": "Gråtone",
        "a11y_reduce_motion": "Reduser bevegelse",
        "a11y_toggle_btn": "Åpne tilgjengelighetsverktøy"
      },
      "ja": {
        "flag": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MTIiIGhlaWdodD0iNTEyIiB2aWV3Qm94PSIwIDAgNTEyIDUxMiI+PG1hc2sgaWQ9ImEiPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMjU2IiBmaWxsPSIjZmZmIi8+PC9tYXNrPjxnIG1hc2s9InVybCgjYSkiPjxwYXRoIGZpbGw9IiNlZWUiIGQ9Ik0wIDBoNTEydjUxMkgweiIvPjxjaXJjbGUgY3g9IjI1NiIgY3k9IjI1NiIgcj0iMTExLjMiIGZpbGw9IiNkODAwMjciLz48L2c+PC9zdmc+",
        "name": "日本語",
        "subtitle": "ウェブ管理パネル",
        "username": "ユーザー名",
        "username_ph": "4〜8文字、半角英数字",
        "email": "メールアドレス",
        "email_ph": "user@example.jp",
        "password": "パスワード",
        "password_ph": "8文字以上",
        "confirm": "パスワード再入力",
        "confirm_ph": "もう一度入力",
        "register": "ログイン",
        "already_registered": "すでにアカウントをお持ちですか？",
        "to_login": "ログインへ",
        "pw_hint": "A-Z, a-z, 0-9",
        "pw_weak": "弱い",
        "pw_medium": "普通",
        "pw_strong": "強い",
        "please_wait": "少々お待ちください...",
        "success_heading": "アカウントが作成されました！",
        "generate": "自動生成",
        "maintenance_heading": "メンテナンスモード",
        "maintenance_text": "新規登録は一時的に停止しています。",
        "tos_prefix": "登録により",
        "tos_link": "利用規約",
        "tos_and": "および",
        "privacy_link": "プライバシーポリシー",
        "did_you_mean": "もしかして",
        "setup_2fa": "コントロールパネルで2要素認証（2FA）を有効にすることをお勧めします。",
        "copy_pw": "コピー",
        "need_help": "お困りですか？",
        "contact_support": "サポートにお問い合わせ",
        "forgot_password": "パスワードをお忘れですか？",
        "pw_req_length": "少なくとも {n} 文字",
        "pw_req_upper": "大文字1文字以上 (A-Z)",
        "pw_req_lower": "小文字1文字以上 (a-z)",
        "pw_req_number": "数字1文字以上 (0-9)",
        "email_mx_invalid": "このメールドメインはメールを受信できないようです。",
        "pw_hibp_warning": "⚠️ このパスワードは {n} 件のデータ流出で見つかりました。",
        "pw_hibp_ok": "✓ 既知の流出データにパスワードは見つかりませんでした。",
        "pw_hibp_checking": "パスワードの安全性を確認中...",
        "invite_code": "招待コード",
        "invite_code_ph": "招待コードを入力",
        "invite_invalid": "無効または使用済みの招待コードです。",
        "demo_notice": "⏱ これはデモアカウントで、{n} 時間後に自動削除されます。",
        "domain": "ドメイン",
        "domain_ph": "example.jp",
        "domain_notice": "登録後、コントロールパネルでドメインを追加してください。",
        "to_panel": "パネルへ",
        "invite_required": "登録には招待コードが必要です。",
        "cookie_banner_text": "セキュリティ（CSRF、セッション）のために必須クッキーを使用しています。続行することで、クッキーの使用に同意したことになります。",
        "cookie_banner_btn": "同意して続行",
        "cookie_banner_label": "クッキーの同意",
        "a11y_widget_label": "アクセシビリティツール",
        "a11y_panel_label": "アクセシビリティオプション",
        "a11y_title": "アクセシビリティ",
        "a11y_font_size": "文字サイズ",
        "a11y_font_dec": "文字サイズを小さく",
        "a11y_font_inc": "文字サイズを大きく",
        "a11y_high_contrast": "ハイコントラスト",
        "a11y_grayscale": "グレースケール",
        "a11y_reduce_motion": "視覚効果を減らす",
        "a11y_toggle_btn": "アクセシビリティツールを開く"
      }
    };

    let currentLang = 'de'; // Set default to German based on request
    function setLanguage(code) {
      currentLang = code;
      const d = I18N[code] || I18N.en;
      localStorage.setItem('fp_lang', code);
      const isRtl = (d.rtl === true || code === 'ar');
      document.documentElement.setAttribute('dir', isRtl ? 'rtl' : 'ltr');
      document.documentElement.setAttribute('lang', code);
      const ll = document.getElementById('currentLangLabel');
      const fl = document.getElementById('currentFlag');
      if (ll) ll.textContent = d.name;
      if (fl) fl.innerHTML = `<img src="${d.flag}" width="20" height="20" alt="${code}" style="border-radius:50%;display:block;object-fit:cover;">`;
      document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.dataset.i18n; if (!d[k]) return;
        let t = d[k];
        if (k === 'demo_notice' && el.dataset.i18nDemoHours) t = t.replace('{n}', el.dataset.i18nDemoHours);
        el.textContent = t;
      });
      document.querySelectorAll('[data-i18n-attr]').forEach(el => {
        const attrPairs = el.dataset.i18nAttr.split('|');
        attrPairs.forEach(pair => {
          const [attrName, key] = pair.split(':');
          if (attrName && key && d[key]) {
            el.setAttribute(attrName, d[key]);
          }
        });
      });

      document.querySelectorAll('[data-i18n-ph]').forEach(el => { const k = el.dataset.i18nPh; if (d[k]) el.placeholder = d[k]; });
      document.querySelectorAll('[data-i18n-min]').forEach(el => {
        const k = el.dataset.i18nMin; const cl = document.getElementById('pwChecklist'); const m = cl ? cl.dataset.min : 8;
        if (d[k]) el.textContent = d[k].replace('{n}', m);
      });
      document.querySelectorAll('.lang-item').forEach(b => b.classList.toggle('active', b.dataset.lang === code));
    }

    const langDropdown = document.getElementById('langDropdown');
    const langBtn = document.getElementById('langBtn');
    if (langDropdown && langBtn) {
      Object.keys(I18N).forEach(code => {
        const item = document.createElement('button');
        item.type = 'button'; item.className = 'lang-item'; item.dataset.lang = code;
        item.innerHTML = `<img src="${I18N[code].flag}" width="20" height="20" alt="${code}" style="border-radius:50%;object-fit:cover;display:block;"> <span>${I18N[code].name}</span>`;
        item.addEventListener('click', () => { setLanguage(code); langDropdown.classList.remove('show'); });
        langDropdown.appendChild(item);
      });
      langBtn.addEventListener('click', e => { e.stopPropagation(); langDropdown.classList.toggle('show'); langBtn.setAttribute('aria-expanded', langDropdown.classList.contains('show')); });
      document.addEventListener('click', e => { const w = document.getElementById('langWrap'); if (w && !w.contains(e.target)) langDropdown.classList.remove('show'); });
      const sl = localStorage.getItem('fp_lang') || 'de';
      setLanguage(I18N[sl] ? sl : 'de');
    }



    // Password meter
    const pwInput = document.getElementById('passwd');
    const pwMeterFill = document.getElementById('pwMeterFill');
    const pwMeterText = document.getElementById('pwMeterText');
    if (pwInput) {
      pwInput.addEventListener('input', function () {
        const v = this.value; if (!v) { pwMeterFill.style.width = '0%'; pwMeterText.textContent = ''; return; }
        let score = 0;
        if (v.length >= <?= PASSWD_MIN_LENGTH ?>) score++;
        if (/[A-Z]/.test(v)) score++; if (/[a-z]/.test(v)) score++; if (/[0-9]/.test(v)) score++; if (/[^A-Za-z0-9]/.test(v)) score++;
        const d = I18N[currentLang] || I18N.en;
        let w = '25%', c = '#e74c4c', l = d.pw_weak || 'Weak';
        if (score >= 4) { w = '100%'; c = '#1089d0'; l = d.pw_strong || 'Strong'; } else if (score >= 3) { w = '65%'; c = '#f0a500'; l = d.pw_medium || 'Medium'; } else if (score >= 2) { w = '35%'; c = '#e74c4c'; }
        pwMeterFill.style.width = w; pwMeterFill.style.backgroundColor = c; pwMeterText.textContent = l; pwMeterText.style.color = c;
      });
    }

    // Password generator
    const genBtn = document.getElementById('generatePwBtn');
    if (genBtn) genBtn.addEventListener('click', () => {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
      let pwd = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[Math.floor(Math.random() * 26)] + "abcdefghijklmnopqrstuvwxyz"[Math.floor(Math.random() * 26)] + "0123456789"[Math.floor(Math.random() * 10)];
      for (let i = 0; i < 9; i++) pwd += chars[Math.floor(Math.random() * chars.length)];
      pwd = pwd.split('').sort(() => 0.5 - Math.random()).join('');
      const p1 = document.getElementById('passwd'), p2 = document.getElementById('passwd2');
      p1.value = pwd; p2.value = pwd; p1.type = 'text'; p2.type = 'text';
      document.querySelectorAll('.eye-btn').forEach(b => { b.querySelector('.show-icon').style.display = 'none'; b.querySelector('.hide-icon').style.display = 'block'; });
      p1.dispatchEvent(new Event('input'));
      const cb = document.getElementById('copyPwBtn'); if (cb) cb.style.display = 'flex';
      setTimeout(() => { p1.type = 'password'; p2.type = 'password'; document.querySelectorAll('.eye-btn').forEach(b => { b.querySelector('.show-icon').style.display = 'block'; b.querySelector('.hide-icon').style.display = 'none'; }); }, 4000);
    });

    // Eye toggle
    document.querySelectorAll('.eye-btn').forEach(btn => {
      btn.addEventListener('click', function () {
        const inp = document.getElementById(this.dataset.target); if (!inp) return;
        const h = inp.type === 'password'; inp.type = h ? 'text' : 'password';
        this.querySelector('.show-icon').style.display = h ? 'none' : 'block';
        this.querySelector('.hide-icon').style.display = h ? 'block' : 'none';
      });
    });

    // Copy password
    const copyPwBtn = document.getElementById('copyPwBtn');
    if (copyPwBtn) {
      copyPwBtn.addEventListener('click', function () {
        const v = document.getElementById('passwd')?.value; if (!v) return;
        navigator.clipboard.writeText(v).then(() => {
          this.classList.add('copied'); const lbl = this.querySelector('#copyPwLabel'), orig = lbl.textContent; lbl.textContent = '✓';
          setTimeout(() => { this.classList.remove('copied'); lbl.textContent = orig; }, 2000);
        });
      });
    }
    if (pwInput) pwInput.addEventListener('input', function () { const cb = document.getElementById('copyPwBtn'); if (cb) cb.style.display = this.value ? 'flex' : 'none'; });

    // Form submit spinner
    const regForm = document.getElementById('regForm');
    if (regForm) {
      regForm.addEventListener('submit', function (e) {
        const u = document.getElementById('username').value.trim();
        const em = document.getElementById('email').value.trim();
        const pw = document.getElementById('passwd').value;
        const pw2 = document.getElementById('passwd2').value;
        if (!/^[a-z0-9]{4,16}$/i.test(u)) { e.preventDefault(); alert('Username: 4-16 characters, only a-z and 0-9 allowed.'); return; }
        if (!em.includes('@')) { e.preventDefault(); alert('Please enter a valid email address.'); return; }
        if (pw.length < <?= PASSWD_MIN_LENGTH ?>) { e.preventDefault(); alert('Password must be at least <?= PASSWD_MIN_LENGTH ?> characters long.'); return; }
        <?php if (PASSWD_REQUIRE_COMPLEXITY): ?>
          if (!/[A-Z]/.test(pw) || !/[a-z]/.test(pw) || !/[0-9]/.test(pw)) { e.preventDefault(); alert('Password must contain at least one uppercase letter, one lowercase letter, and one number.'); return; }
        <?php endif; ?>
        if (pw !== pw2) { e.preventDefault(); alert('Passwords do not match.'); return; }
        const btn = document.getElementById('submitBtn'), sp = document.getElementById('spinner'), lbl = document.getElementById('submitLabel');
        if (sp) sp.style.display = 'block';
        const cl = localStorage.getItem('fp_lang') || 'en';
        if (lbl) lbl.textContent = (I18N[cl] || I18N.en).please_wait || 'Please wait...';
        setTimeout(() => { if (btn) btn.disabled = true; }, 10);
      });
    }

    // Preloader
    window.addEventListener('load', () => { const p = document.getElementById('preloader'); if (p) { p.classList.add('hidden'); p.addEventListener('transitionend', () => p.remove(), { once: true }); } });

    // Email typo detection
    const emailInput = document.getElementById('email'), emailSug = document.getElementById('emailSuggestion'), emailSugLink = document.getElementById('emailSuggestionLink');
    if (emailInput && emailSug && emailSugLink) {
      const cds = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'gmx.de', 'gmx.net', 'gmx.at', 'web.de', 't-online.de', 'posteo.de', 'mailbox.org', 'yandex.ru', 'mail.ru', 'proton.me', 'protonmail.com', 'tuta.com', 'live.com', 'zoho.com'];
      function dist(a, b) { if (!a.length) return b.length; if (!b.length) return a.length; const m = []; for (let i = 0; i <= b.length; i++)m[i] = [i]; for (let j = 0; j <= a.length; j++)m[0][j] = j; for (let i = 1; i <= b.length; i++)for (let j = 1; j <= a.length; j++)m[i][j] = b[i - 1] === a[j - 1] ? m[i - 1][j - 1] : Math.min(m[i - 1][j - 1] + 1, m[i][j - 1] + 1, m[i - 1][j] + 1); return m[b.length][a.length]; }
      emailInput.addEventListener('blur', function () {
        const v = this.value.trim().toLowerCase(), pts = v.split('@');
        if (pts.length === 2 && pts[1]) {
          const u = pts[0], dom = pts[1];
          if (cds.includes(dom)) { emailSug.style.display = 'none'; return; }
          let bm = null, md = 3;
          for (const cd of cds) { const d = dist(dom, cd); if (d < md) { md = d; bm = cd; } }
          if (bm && bm !== dom) { const se = u + '@' + bm; emailSugLink.textContent = se; emailSug.style.display = 'block'; emailSugLink.onclick = e => { e.preventDefault(); emailInput.value = se; emailSug.style.display = 'none'; emailInput.focus(); }; }
          else emailSug.style.display = 'none';
        } else emailSug.style.display = 'none';
      });
    }

    // Help FAB
    window.addEventListener('click', e => { const hm = document.getElementById('helpMenu'); if (hm && hm.classList.contains('show') && !e.target.closest('#helpFabWrap')) hm.classList.remove('show'); });
    const helpFabBtn = document.getElementById('helpFabBtn'); if (helpFabBtn) helpFabBtn.addEventListener('click', e => { e.stopPropagation(); document.getElementById('helpMenu').classList.toggle('show'); });

    // Password checklist
    (function () {
      const cl = document.getElementById('pwChecklist'); if (!cl) return;
      const min = parseInt(cl.dataset.min, 10) || 8, complex = cl.dataset.complexity === '1', inp = document.getElementById('passwd'); if (!inp) return;
      const chkL = document.getElementById('chk-length'), chkU = document.getElementById('chk-upper'), chkLo = document.getElementById('chk-lower'), chkN = document.getElementById('chk-number');
      function sc(el, ok) { if (!el) return; el.classList.toggle('ok', ok); el.querySelector('.check-icon').textContent = ok ? '✓' : ''; }
      function upd() {
        const v = inp.value; sc(chkL, v.length >= min); if (complex) { sc(chkU, /[A-Z]/.test(v)); sc(chkLo, /[a-z]/.test(v)); sc(chkN, /[0-9]/.test(v)); }
        if (chkL) { const sp = chkL.querySelector('[data-i18n-min]'); if (sp) { const k = sp.dataset.i18nMin, d = I18N[currentLang] || I18N.en, tpl = d[k] || `At least ${min} characters`; sp.textContent = tpl.replace('{n}', min); } }
      }
      inp.addEventListener('input', upd); upd();
    })();

    <?php if (defined('ENABLE_HIBP_CHECK') && ENABLE_HIBP_CHECK): ?>
        (function () {
          const inp = document.getElementById('passwd'), hs = document.getElementById('hibpStatus'), form = document.getElementById('regForm');
          if (!inp || !hs) return;
          const block = <?= defined('HIBP_BLOCK_ON_BREACH') && HIBP_BLOCK_ON_BREACH ? 'true' : 'false' ?>;
          let t = null, lb = false;
          async function sha1(s) { const b = new TextEncoder().encode(s), h = await crypto.subtle.digest('SHA-1', b); return Array.from(new Uint8Array(h)).map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase(); }
          async function chk(pw) {
            if (pw.length < 4) { hs.className = 'hibp-status'; lb = false; return; }
            const d = I18N[currentLang] || I18N.en; hs.className = 'hibp-status checking'; hs.textContent = d.pw_hibp_checking || 'Checking...';
            try {
              const h = await sha1(pw), p = h.slice(0, 5), sx = h.slice(5), r = await fetch(`https://api.pwnedpasswords.com/range/${p}`, { headers: { 'Add-Padding': 'true' } });
              if (!r.ok) throw 0; const tx = await r.text(); let c = 0;
              for (const l of tx.split('\n')) { const [s, ct] = l.trim().split(':'); if (s && s.toUpperCase() === sx) { c = parseInt(ct, 10) || 1; break; } }
              if (c > 0) { lb = true; hs.className = 'hibp-status warning'; hs.textContent = (d.pw_hibp_warning || '⚠️ {n} breach(es).').replace('{n}', c.toLocaleString()); }
              else { lb = false; hs.className = 'hibp-status ok'; hs.textContent = d.pw_hibp_ok || '✓ Password safe.'; }
            } catch { hs.className = 'hibp-status'; lb = false; }
          }
          inp.addEventListener('input', function () { clearTimeout(t); t = setTimeout(() => chk(inp.value), 800); });
          if (block && form) form.addEventListener('submit', function (e) { if (lb) { e.preventDefault(); const d = I18N[currentLang] || I18N.en; hs.className = 'hibp-status warning'; hs.textContent = (d.pw_hibp_warning || '⚠️ Please change your password.').replace('{n}', '?'); inp.focus(); } }, true);
        })();
    <?php endif; ?>
  </script>
  <?php if (defined('COOKIE_BANNER_ENABLED') && COOKIE_BANNER_ENABLED): ?>
    <script>
        (function () { const b = document.getElementById('cookieBanner'); if (!b) return; const K = 'fp_cookie_consent'; if (localStorage.getItem(K) !== '1') setTimeout(() => b.classList.add('visible'), 400); const ab = document.getElementById('cookieAcceptBtn'); if (ab) ab.addEventListener('click', function () { localStorage.setItem(K, '1'); b.classList.remove('visible'); b.addEventListener('transitionend', () => b.remove(), { once: true }); }); })();
    </script>
  <?php endif; ?>
  <?php if (defined('ACCESSIBILITY_WIDGET_ENABLED') && ACCESSIBILITY_WIDGET_ENABLED): ?>
    <script>
      (function () { const tb = document.getElementById('a11yToggleBtn'), pan = document.getElementById('a11yPanel'), fd = document.getElementById('a11yFontDec'), fi = document.getElementById('a11yFontInc'), fl = document.getElementById('a11yFontSize'), cc = document.getElementById('a11yContrast'), gc = document.getElementById('a11yGrayscale'), mc = document.getElementById('a11yMotion'); const S = 'fp_a11y'; let st = { font: 100, contrast: false, grayscale: false, motion: false }; try { const sv = JSON.parse(localStorage.getItem(S) || 'null'); if (sv) st = { ...st, ...sv }; } catch (e) { } function save() { try { localStorage.setItem(S, JSON.stringify(st)); } catch (e) { } } function apply() { document.documentElement.style.fontSize = st.font + '%'; fl.textContent = st.font + '%'; document.documentElement.classList.toggle('a11y-contrast', st.contrast); document.documentElement.classList.toggle('a11y-grayscale', st.grayscale); document.documentElement.classList.toggle('a11y-motion', st.motion); cc.checked = st.contrast; gc.checked = st.grayscale; mc.checked = st.motion; } if (!document.getElementById('a11y-rules')) { const s = document.createElement('style'); s.id = 'a11y-rules'; s.textContent = '.a11y-contrast{filter:contrast(1.6) brightness(1.05);}.a11y-grayscale{filter:grayscale(1);}.a11y-contrast.a11y-grayscale{filter:contrast(1.6) brightness(1.05) grayscale(1);}.a11y-motion *,.a11y-motion *::before,.a11y-motion *::after{animation-duration:.001ms!important;transition-duration:.001ms!important;}'; document.head.appendChild(s); } apply(); tb.addEventListener('click', function (e) { e.stopPropagation(); const o = pan.classList.toggle('open'); tb.setAttribute('aria-expanded', o ? 'true' : 'false'); }); document.addEventListener('click', function (e) { const w = document.getElementById('a11yWidget'); if (w && !w.contains(e.target)) { pan.classList.remove('open'); tb.setAttribute('aria-expanded', 'false'); } }); fd.addEventListener('click', () => { st.font = Math.max(80, st.font - 10); apply(); save(); }); fi.addEventListener('click', () => { st.font = Math.min(150, st.font + 10); apply(); save(); }); cc.addEventListener('change', function () { st.contrast = this.checked; apply(); save(); }); gc.addEventListener('change', function () { st.grayscale = this.checked; apply(); save(); }); mc.addEventListener('change', function () { st.motion = this.checked; apply(); save(); }); })();
    </script>
  <?php endif; ?>
</body>

</html>