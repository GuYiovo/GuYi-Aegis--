<?php
// auth_check.php - 统一验证文件
session_start();

// 调试模式
define('DEBUG_MODE', true);

// 验证函数
function checkAuth() {
    // 检查是否已验证
    if (!isset($_SESSION['verified']) || $_SESSION['verified'] !== true) {
        if (DEBUG_MODE) error_log("未验证，SESSION: " . print_r($_SESSION, true));
        header('Location: /index.php?error=请先完成验证');
        exit();
    }
    
    // 检查用户代理是否一致（防止会话劫持）
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        if (DEBUG_MODE) error_log("用户代理不匹配");
        session_unset();
        session_destroy();
        header('Location: /index.php?error=安全异常，请重新验证');
        exit();
    }
    
    // 检查卡密是否过期
    if (isset($_SESSION['expire_time']) && strtotime($_SESSION['expire_time']) < time()) {
        if (DEBUG_MODE) error_log("卡密已过期: " . ($_SESSION['expire_time'] ?? ''));
        session_unset();
        session_destroy();
        header('Location: /index.php?error=卡密已过期');
        exit();
    }
    
    // 检查会话时间（8小时有效期）
    $session_timeout = 8 * 3600;
    if (isset($_SESSION['verified_at']) && (time() - $_SESSION['verified_at'] > $session_timeout)) {
        if (DEBUG_MODE) error_log("会话超时");
        session_unset();
        session_destroy();
        header('Location: /index.php?error=会话已过期，请重新验证');
        exit();
    }
    
    // 更新最后活动时间
    $_SESSION['last_activity'] = time();
    
    // 验证通过
    return true;
}

// 获取用户信息函数
function getUserInfo() {
    return [
        'card_code' => $_SESSION['card_code'] ?? null,
        'verified_at' => $_SESSION['verified_at'] ?? null,
        'expire_time' => $_SESSION['expire_time'] ?? null,
        'device_hash' => $_SESSION['device_hash'] ?? null
    ];
}

// 检查剩余时间函数
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