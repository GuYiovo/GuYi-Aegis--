<?php
// config.php - Enterprise Security Core
// 1. 安全响应头
header("X-Frame-Options: SAMEORIGIN"); // 防止点击劫持
header("X-XSS-Protection: 1; mode=block"); // XSS防护
header("X-Content-Type-Options: nosniff"); // 禁止MIME嗅探
header("Referrer-Policy: strict-origin-when-cross-origin");

// 2. 错误处理
error_reporting(0); // 生产环境关闭错误显示
ini_set('display_errors', 0);

// 3. 系统密钥 (用于Cookie签名和CSRF令牌，请修改此字符串)
define('SYS_SECRET', 'ENT_SECure_K3y_@9928_CHANGE_THIS_TO_RANDOM');

// 4. 路径与数据库保护
$base_dir = __DIR__;
$db_dir = $base_dir . '/data';

if (!is_dir($db_dir)) {
    if (!mkdir($db_dir, 0755, true)) {
        die('System Error: Cannot create data directory.');
    }
}

// 自动写入 .htaccess 禁止直接下载 .db 文件 (针对 Apache/LiteSpeed)
$htaccess = $db_dir . '/.htaccess';
if (!file_exists($htaccess)) {
    file_put_contents($htaccess, "Order Deny,Allow\nDeny from all");
}

define('DB_PATH', $db_dir . '/cards.db');

// 卡类型配置
define('CARD_TYPES', [
    'hour' => ['name' => '小时卡', 'duration' => 3600],
    'day' => ['name' => '天卡', 'duration' => 86400],
    'week' => ['name' => '周卡', 'duration' => 604800],
    'month' => ['name' => '月卡', 'duration' => 2592000],
    'season' => ['name' => '季卡', 'duration' => 7776000],
    'year' => ['name' => '年卡', 'duration' => 31536000],
]);
?>
