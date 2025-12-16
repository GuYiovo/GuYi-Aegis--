<?php
// config.php - 系统核心配置与引导

// ------------------------------------------
// 核心引导逻辑：检测安装状态
// ------------------------------------------

// 检查是否已定义 DB_INSTALLED_CHECK 常量
// 该常量只有在 install.php 成功运行并重写 config.php 后才会存在
if (!defined('DB_INSTALLED_CHECK')) {
    
    // 获取当前访问的文件名
    $current_script = basename($_SERVER['SCRIPT_NAME']);
    
    // 如果当前不是在访问 install.php，并且 install.php 文件还存在
    if ($current_script !== 'install.php' && file_exists(__DIR__ . '/install.php')) {
        // 强制跳转到安装界面
        header('Location: install.php');
        exit();
    }
    
    // 如果 install.php 已经被删了或者是改名了，为了防止报错，定义默认空值
    // 这样 index.php 不会因为缺常量而直接挂掉，虽然连不上库
    define('DB_HOST', 'localhost');
    define('DB_NAME', '');
    define('DB_USER', '');
    define('DB_PASS', '');
}

// ------------------------------------------
// 下面的内容在【未安装】时是占位符
// 在【安装后】会被 install.php 自动替换为真实配置
// ------------------------------------------

// 预定义卡密类型（防止安装前报错）
if (!defined('CARD_TYPES')) {
    define('CARD_TYPES', []);
}
?>
