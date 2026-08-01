<?php

/**
 * Developer: Andy Goldau
 * © 2026 FP-Register by PanelLayer. All rights reserved.
 * DISCLAIMER: Not affiliated with P.A.G.M. OU (FASTPANEL).
 *
 * Demo Mode Cron Cleanup – FastPanel Edition
 * -------------------------------------------
 * Deletes expired demo accounts via the FastPanel REST API.
 *
 * Setup (crontab -e):
 *   // runs every 30 minutes:
 *   30 min: slash-30 star star star star   php /path/to/cron_cleanup.php >> /dev/null 2>&1
 *
 * IMPORTANT: Run this script from the CLI only (not via a web browser).
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('CLI only.');
}

error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/config.php';

// Demo mode guard
if (!defined('DEMO_MODE') || !DEMO_MODE) {
    echo "[" . date('c') . "] Demo mode is disabled. Nothing to do.\n";
    exit(0);
}

$demoFile = defined('DEMO_ACCOUNTS_FILE') ? DEMO_ACCOUNTS_FILE : (__DIR__ . '/data/demo_accounts.json');

if (!is_file($demoFile)) {
    echo "[" . date('c') . "] No demo accounts file found at: $demoFile\n";
    exit(0);
}

$accounts = json_decode(file_get_contents($demoFile), true);
if (!is_array($accounts) || empty($accounts)) {
    echo "[" . date('c') . "] No demo accounts to process.\n";
    exit(0);
}

$now     = time();
$deleted = [];
$failed  = [];
$skipped = [];

foreach ($accounts as $username => $info) {
    $deleteAfter = (int)($info['delete_after'] ?? 0);

    if ($now < $deleteAfter) {
        $remaining = $deleteAfter - $now;
        echo "[" . date('c') . "] SKIP  '{$username}' – expires in " . gmdate('H:i:s', $remaining) . "\n";
        $skipped[] = $username;
        continue;
    }

    echo "[" . date('c') . "] DELETE '{$username}' (expired " . date('Y-m-d H:i:s', $deleteAfter) . ") ...\n";
    $result = fpDeleteUser($username);

    if ($result['success']) {
        echo "[" . date('c') . "] OK     '{$username}' deleted via FastPanel API.\n";
        $deleted[] = $username;
    } else {
        echo "[" . date('c') . "] ERROR  '{$username}': " . $result['message'] . "\n";
        // Keep in list if deletion failed to retry next run
        $failed[] = $username;
    }
}

// Remove successfully deleted accounts from the tracking file
foreach ($deleted as $username) {
    unset($accounts[$username]);
}

// Persist updated list
$fp = fopen($demoFile, 'w');
if ($fp) {
    flock($fp, LOCK_EX);
    fwrite($fp, json_encode($accounts, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
}

echo "\n[" . date('c') . "] Summary: " . count($deleted) . " deleted, " . count($failed) . " failed, " . count($skipped) . " skipped.\n";
exit(empty($failed) ? 0 : 1);

// ── FastPanel API: Delete User ─────────────────────────────────────────────
/**
 * Deletes a FastPanel user by login name via DELETE /api/users/{login}.
 * FastPanel may respond synchronously (200/204) or asynchronously (202 + queue).
 */
function fpDeleteUser(string $username): array
{
    $username = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $username);
    if (!$username) {
        return ['success' => false, 'message' => 'Invalid username.'];
    }

    // Step 1: Look up the user's numeric ID (required for DELETE)
    $userId = fpGetUserId($username);
    if ($userId === null) {
        // User not found on server – treat as already deleted
        echo "[" . date('c') . "] INFO   '{$username}' not found on FastPanel server (already deleted?).\n";
        return ['success' => true, 'message' => 'User not found on server.'];
    }
    if ($userId === false) {
        return ['success' => false, 'message' => 'Failed to look up user ID for "' . $username . '".'];
    }

    // Step 2: DELETE /api/users/{id}
    $url = FP_HOST . ':' . FP_PORT . '/api/users/' . $userId;
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => 'DELETE',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_HTTPHEADER     => ['Authorization: ' . FP_API_TOKEN, 'Accept: application/json'],
        CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY,
        CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 30,
    ]);
    $response   = curl_exec($ch);
    $httpCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $errno      = curl_errno($ch);
    $errorMsg   = curl_error($ch);
    curl_close($ch);

    if ($errno) {
        return ['success' => false, 'message' => 'cURL error: ' . $errorMsg];
    }

    // 204 No Content or 200 OK = immediate success
    if ($httpCode === 204 || $httpCode === 200) {
        return ['success' => true, 'message' => 'Deleted (HTTP ' . $httpCode . ').'];
    }

    // 202 Accepted = async queue
    if ($httpCode === 202) {
        $headers = substr((string)$response, 0, $headerSize);
        if (preg_match('/Queue-Event-ID:\s*([^\r\n]+)/i', $headers, $m)) {
            $queueId = trim($m[1]);
            if ($queueId) {
                return fpPollQueueDelete($queueId);
            }
        }
        // No queue ID header – optimistically assume success
        return ['success' => true, 'message' => 'Deletion queued (no queue ID).'];
    }

    if ($httpCode === 404) {
        return ['success' => true, 'message' => 'User not found (already deleted).'];
    }

    $body = substr((string)$response, $headerSize);
    $json = json_decode($body, true);
    $msg  = $json['message'] ?? $json['detail'] ?? ('HTTP ' . $httpCode);
    return ['success' => false, 'message' => (string)$msg];
}

// ── Fetch user numeric ID from FastPanel ───────────────────────────────────
/**
 * Returns the integer user ID, null if user not found, or false on error.
 */
function fpGetUserId(string $username)
{
    // Try GET /api/users?login=<username> first
    $url = FP_HOST . ':' . FP_PORT . '/api/users?' . http_build_query(['login' => $username]);
    $ch  = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ['Authorization: ' . FP_API_TOKEN, 'Accept: application/json'],
        CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY,
        CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 15,
    ]);
    $resp     = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno    = curl_errno($ch);
    curl_close($ch);

    if ($errno || $httpCode !== 200 || !$resp) return false;

    $json = json_decode((string)$resp, true);
    if (!is_array($json)) return false;

    // FastPanel returns { data: [ { id, login, ... }, ... ] } or just an array
    $list = $json['data'] ?? $json;
    if (!is_array($list)) return false;

    foreach ($list as $user) {
        if (is_array($user) && strtolower($user['login'] ?? '') === strtolower($username)) {
            return (int)$user['id'];
        }
    }
    return null; // Not found
}

// ── Poll queue for async delete completion ─────────────────────────────────
function fpPollQueueDelete(string $queueId): array
{
    $url      = FP_HOST . ':' . FP_PORT . '/api/queue/' . rawurlencode($queueId) . '/event';
    $attempts = defined('FP_QUEUE_POLL_ATTEMPTS') ? (int)FP_QUEUE_POLL_ATTEMPTS : 6;
    $sleep    = defined('FP_QUEUE_POLL_SLEEP')    ? (int)FP_QUEUE_POLL_SLEEP    : 4;

    for ($i = 0; $i < $attempts; $i++) {
        sleep($sleep);
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Authorization: ' . FP_API_TOKEN, 'Accept: application/json'],
            CURLOPT_SSL_VERIFYPEER => FP_SSL_VERIFY,
            CURLOPT_SSL_VERIFYHOST => FP_SSL_VERIFY ? 2 : 0,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 15,
        ]);
        $resp  = curl_exec($ch);
        $errno = curl_errno($ch);
        curl_close($ch);

        if ($errno || !$resp) continue;
        $json   = json_decode((string)$resp, true);
        if (!is_array($json)) continue;
        $status = strtoupper($json['status'] ?? $json['event_status'] ?? '');

        if ($status === 'SUCCESS') return ['success' => true, 'message' => 'Deleted via queue.'];
        if (in_array($status, ['FAILED', 'FAILURE', 'ERROR'], true)) {
            $msg = $json['result']['error'] ?? $json['message'] ?? 'Queue deletion failed.';
            return ['success' => false, 'message' => (string)$msg];
        }
    }
    return ['success' => false, 'message' => 'Queue polling timed out for delete operation.'];
}
