<?php
// auth_check.php - 统一验证文件
session_start();

define('DEBUG_MODE', true);

function checkAuth() {
    if (!isset($_SESSION['verified']) || $_SESSION['verified'] !== true) {
        if (DEBUG_MODE) error_log("未验证，SESSION: " . print_r($_SESSION, true));
        header('Location: /index.php?error=请先完成验证');
        exit();
    }
    
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        if (DEBUG_MODE) error_log("用户代理不匹配");
        session_unset();
        session_destroy();
        header('Location: /index.php?error=安全异常，请重新验证');
        exit();
    }
    
    // 严格判断：使用 <=，确保到期那一秒也算过期
    if (isset($_SESSION['expire_time']) && strtotime($_SESSION['expire_time']) <= time()) {
        if (DEBUG_MODE) error_log("卡密已过期: " . ($_SESSION['expire_time'] ?? ''));
        session_unset();
        session_destroy();
        header('Location: /index.php?error=卡密已过期');
        exit();
    }
    
    $session_timeout = 8 * 3600;
    if (isset($_SESSION['verified_at']) && (time() - $_SESSION['verified_at'] > $session_timeout)) {
        if (DEBUG_MODE) error_log("会话超时");
        session_unset();
        session_destroy();
        header('Location: /index.php?error=会话已过期，请重新验证');
        exit();
    }
    
    $_SESSION['last_activity'] = time();
    return true;
}

function getUserInfo() {
    return [
        'card_code' => $_SESSION['card_code'] ?? null,
        'verified_at' => $_SESSION['verified_at'] ?? null,
        'expire_time' => $_SESSION['expire_time'] ?? null,
        'device_hash' => $_SESSION['device_hash'] ?? null
    ];
}

function getRemainingTime() {
    if (isset($_SESSION['expire_time'])) {
        $remaining = strtotime($_SESSION['expire_time']) - time();
        if ($remaining > 0) {
            $hours = floor($remaining / 3600);
            $minutes = floor(($remaining % 3600) / 60);
            $seconds = $remaining % 60;
            return [
                'total_seconds' => $remaining,
                'hours' => $hours,
                'minutes' => $minutes,
                'seconds' => $seconds,
                'formatted' => $hours > 0 ? "{$hours}小时{$minutes}分钟" : "{$minutes}分钟{$seconds}秒"
            ];
        }
    }
    return null;
}
?>
