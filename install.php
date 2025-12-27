<?php
error_reporting(0); // 安装过程不显示PHP错误，减少干扰

// 获取当前步骤
$step = isset($_GET['step']) ? intval($_GET['step']) : 1;
$msg = '';
$msg_type = ''; 

// 检测设备类型 (用于背景图)
$is_mobile_client = preg_match("/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|mobi|palm|phone|pie|samsung|scp|wap|windows ce;iemobile|xhtml\\+xml)/i", $_SERVER["HTTP_USER_AGENT"]);
$bg_url = $is_mobile_client ? 'backend/pjt.png' : 'backend/pcpjt.png';

// ----------------------
// 核心逻辑区域
// ----------------------

function check_env() {
    $results = [];
    $php_version = phpversion();
    $results[] = [
        'icon' => '<path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>', 
        'name' => 'PHP 版本 (> 7.2)',
        'info' => '当前: ' . $php_version,
        'status' => version_compare($php_version, '7.2.0', '>=')
    ];
    $results[] = [
        'icon' => '<path d="M4 7c0-1.657 3.582-3 8-3s8 1.343 8 3v10c0 1.657-3.582 3-8 3S4 18.657 4 17V7z"/><path d="M4 12c0 1.657 3.582 3 8 3s8-1.343 8-3"/>', 
        'name' => 'MySQL 扩展 (PDO)',
        'info' => extension_loaded('pdo_mysql') ? '已安装' : '未安装',
        'status' => extension_loaded('pdo_mysql')
    ];
    $is_writable = is_writable(__DIR__ . DIRECTORY_SEPARATOR . 'config.php') || is_writable(__DIR__);
    $results[] = [
        'icon' => '<path d="M11 5h2M12 17v.01M3 11h18M5 11a7 7 0 0114 0v3.18c0 .53.21 1.04.59 1.41l.12.12c.78.78.78 2.05 0 2.83l-.12.12a2.99 2.99 0 01-2.12.88H6.54c-1.11 0-2.08-.63-2.54-1.58l-.27-.55A2.99 2.99 0 014 15.18V11z"/>', 
        'name' => '根目录写入权限',
        'info' => $is_writable ? '可写' : '不可写 (请检查目录权限)',
        'status' => $is_writable
    ];
    return $results;
}

// 提交数据库信息处理
if ($step == 3 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = trim($_POST['db_host']);
    $name = trim($_POST['db_name']);
    $user = trim($_POST['db_user']);
    $pass = trim($_POST['db_pass']);
    $port = trim($_POST['db_port']);

    if(empty($host) || empty($name) || empty($user)) {
        $msg = "请填写完整信息";
        $msg_type = 'error';
        $step = 2; // 返回上一步
    } else {
        try {
            $dsn = "mysql:host=$host;port=$port;dbname=$name;charset=utf8mb4";
            $pdo = new PDO($dsn, $user, $pass);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $secret = 'SYS_' . md5(uniqid('', true));
            $config_content = "<?php
// config.php - System Configuration
// 此文件存在意味着系统已安装
define('DB_INSTALLED_CHECK', true);

// 1. 安全头
header(\"X-Frame-Options: SAMEORIGIN\");
header(\"X-XSS-Protection: 1; mode=block\");
header(\"X-Content-Type-Options: nosniff\");

// 2. 数据库配置
define('SYS_SECRET', '$secret');
define('DB_HOST', '$host');
define('DB_NAME', '$name');
define('DB_USER', '$user');
define('DB_PASS', '$pass');
define('DB_PORT', '$port');

// 3. 全局设置
error_reporting(0);
ini_set('display_errors', 0);

// 卡类型配置
define('CARD_TYPES', [
    'hour' => ['name' => '小时卡', 'duration' => 3600],
    'day' => ['name' => '天卡', 'duration' => 86400],
    'week' => ['name' => '周卡', 'duration' => 604800],
    'month' => ['name' => '月卡', 'duration' => 2592000],
    'season' => ['name' => '季卡', 'duration' => 7776000],
    'year' => ['name' => '年卡', 'duration' => 31536000],
]);
?>";
            $config_file_path = __DIR__ . DIRECTORY_SEPARATOR . 'config.php';
            if (file_put_contents($config_file_path, $config_content)) {
                
                $install_file_path = __FILE__;
                $deleted = false;
                $delete_error_message = '';

                if (!@unlink($install_file_path)) {
                    $new_install_file_path = $install_file_path . '.disabled';
                    if (@rename($install_file_path, $new_install_file_path)) {
                        $delete_error_message = "无法直接删除 install.php，已将其重命名为 `install.php.disabled`。请务必手动删除或移动此文件以确保安全。";
                    } else {
                        $delete_error_message = "系统权限不足，无法自动删除或重命名 `install.php`。<strong>请务必立即手动删除此文件！</strong>否则您的网站随时可能被重置。";
                    }
                } else {
                    $deleted = true;
                }
                
                $step = 3; 
            } else {
                $msg = "写入配置文件失败，请检查目录权限 (`{$config_file_path}`)";
                $msg_type = 'error';
                $step = 2; // 返回上一步
            }
        } catch (PDOException $e) {
            $msg = "数据库连接失败: " . $e->getMessage();
            $msg_type = 'error';
            $step = 2; // 返回上一步
        }
    }
}

$env_data = check_env();
$env_pass = !in_array(false, array_column($env_data, 'status'));
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统初始化安装</title>
    <link rel="shortcut icon" href="backend/logo.png" type="image/png">
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: rgba(15, 23, 42, 0.65); /* 半透明背景 */
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --text-main: #f1f5f9;
            --text-sub: #94a3b8;
            --border: rgba(255, 255, 255, 0.15);
            --success: #10b981;
            --error: #ef4444;
        }
        body {
            margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-dark);
            /* 背景图逻辑 */
            background-image: url('<?php echo $bg_url; ?>');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            color: var(--text-main);
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
            overflow: hidden;
        }
        
        /* 飘落特效 CSS */
        .ay-petals { position: fixed; inset: 0; pointer-events: none; overflow: hidden; z-index: 1; }
        .ay-petals i {
            position: absolute; width: 12px; height: 10px;
            /* 修改为樱花色渐变 */
            background: linear-gradient(135deg, #ffd1e6, #ff9aca); 
            border-radius: 80% 80% 80% 20% / 80% 80% 20% 80%;
            opacity: .5; filter: blur(.2px);
            animation: ay-fall linear infinite; transform: rotate(20deg);
        }
        .ay-petals i:nth-child(3n) { width: 9px; height: 7px; animation-duration: 12s; }
        .ay-petals i:nth-child(4n) { animation-duration: 10s; opacity: .35; }
        .ay-petals i:nth-child(5n) { width: 14px; height: 12px; animation-duration: 14s; }
        @keyframes ay-fall { to { transform: translateY(110vh) rotate(360deg); } }

        .container {
            width: 100%; max-width: 460px; background: var(--card-bg);
            /* 高斯模糊 */
            backdrop-filter: blur(20px) saturate(140%);
            -webkit-backdrop-filter: blur(20px) saturate(140%);
            border: 1px solid var(--border); border-radius: 20px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); padding: 40px;
            position: relative; z-index: 10;
        }
        .header { text-align: center; margin-bottom: 35px; }
        .logo { font-size: 24px; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; color: transparent; margin-bottom: 8px; display: inline-block; }
        .steps { display: flex; justify-content: center; gap: 8px; margin-top: 15px; }
        .step-dot { width: 40px; height: 4px; border-radius: 2px; background: rgba(255,255,255,0.1); transition: 0.3s; }
        .step-dot.active { background: var(--primary); box-shadow: 0 0 10px rgba(59, 130, 246, 0.5); }
        h2 { font-size: 18px; font-weight: 600; margin: 0 0 20px 0; display: flex; align-items: center; gap: 10px; }
        .icon-svg { width: 20px; height: 20px; stroke-width: 2; stroke: currentColor; fill: none; stroke-linecap: round; stroke-linejoin: round; }
        .check-list { display: flex; flex-direction: column; gap: 12px; }
        .check-item { display: flex; align-items: center; justify-content: space-between; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 12px; transition: 0.2s; }
        .check-left { display: flex; align-items: center; gap: 12px; }
        .check-icon { color: var(--text-sub); display: flex; }
        .check-info h4 { margin: 0; font-size: 14px; }
        .check-info p { margin: 2px 0 0 0; font-size: 12px; color: var(--text-sub); }
        .status-badge { font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 20px; }
        .pass { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        .fail { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; font-size: 13px; color: var(--text-sub); margin-bottom: 8px; font-weight: 500; }
        input { width: 100%; box-sizing: border-box; background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); color: white; padding: 14px 16px; border-radius: 10px; font-size: 14px; transition: all 0.2s; outline: none; }
        input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }
        .btn-primary { width: 100%; padding: 16px; background: linear-gradient(135deg, var(--primary), var(--primary-hover)); color: white; border: none; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 24px; transition: 0.2s; }
        .btn-primary:hover { filter: brightness(1.1); transform: translateY(-1px); }
        .btn-primary:disabled { background: #334155; cursor: not-allowed; opacity: 0.7; }
        .alert { padding: 14px; border-radius: 10px; margin-bottom: 20px; font-size: 13px; display: flex; align-items: center; gap: 10px; }
        .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #fca5a5; }
        .success-box { text-align: center; padding: 20px 0; }
        .success-icon { width: 80px; height: 80px; background: rgba(16, 185, 129, 0.1); border-radius: 50%; color: var(--success); display: flex; align-items: center; justify-content: center; margin: 0 auto 20px auto; }
        .delete-notice { background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; margin: 20px 0; font-size: 13px; text-align: left; line-height: 1.5; border: 1px solid rgba(255,255,255,0.05); }
    </style>
</head>
<body>

<!-- 飘落特效容器 -->
<div class="ay-petals" aria-hidden="true">
    <i style="left:6%; top:-8vh; animation-duration:11s"></i>
    <i style="left:24%; top:-12vh; animation-duration:13s"></i>
    <i style="left:52%; top:-16vh; animation-duration:12s"></i>
    <i style="left:72%; top:-10vh; animation-duration:10s"></i>
    <i style="left:86%; top:-18vh; animation-duration:14s"></i>
</div>

<div class="container">
    <div class="header">
        <div class="logo">System Initialization</div>
        <div class="steps">
            <div class="step-dot <?php echo $step >= 1 ? 'active' : ''; ?>"></div>
            <div class="step-dot <?php echo $step >= 2 ? 'active' : ''; ?>"></div>
            <div class="step-dot <?php echo $step >= 3 ? 'active' : ''; ?>"></div>
        </div>
    </div>
    <?php if($msg): ?>
        <div class="alert alert-<?php echo $msg_type; ?>"><?php echo $msg; ?></div>
    <?php endif; ?>

    <!-- STEP 1 -->
    <?php if ($step == 1): ?>
        <h2>环境检查</h2>
        <div class="check-list">
            <?php foreach($env_data as $item): ?>
            <div class="check-item">
                <div class="check-left">
                    <div class="check-icon"><svg class="icon-svg" viewBox="0 0 24 24"><?php echo $item['icon']; ?></svg></div>
                    <div class="check-info"><h4><?php echo $item['name']; ?></h4><p><?php echo $item['info']; ?></p></div>
                </div>
                <div class="status-badge <?php echo $item['status'] ? 'pass' : 'fail'; ?>"><?php echo $item['status'] ? '通过' : '失败'; ?></div>
            </div>
            <?php endforeach; ?>
        </div>
        <button class="btn-primary" <?php echo $env_pass ? '' : 'disabled'; ?> onclick="window.location.href='?step=2'">下一步</button>
    
    <!-- STEP 2 -->
    <?php elseif ($step == 2): ?>
        <h2>数据库配置</h2>
        <form method="POST" action="?step=3">
            <div class="form-group"><label>数据库地址</label><input type="text" name="db_host" value="localhost"></div>
            <div class="form-group" style="display:flex;gap:15px;">
                <div style="flex:1;"><label>数据库名</label><input type="text" name="db_name" required></div>
                <div style="width:80px;"><label>端口</label><input type="text" name="db_port" value="3306"></div>
            </div>
            <div class="form-group"><label>用户名</label><input type="text" name="db_user" required></div>
            <div class="form-group"><label>密码</label><input type="password" name="db_pass" required></div>
            <button type="submit" class="btn-primary">立即安装</button>
        </form>

    <!-- STEP 3 -->
    <?php elseif ($step == 3): ?>
        <div class="success-box">
            <div class="success-icon"><svg class="icon-svg" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg></div>
            <h2>安装成功!</h2>
            <p style="color:var(--text-sub);font-size:14px; margin-bottom: 20px;">系统已就绪，配置文件已锁定。</p>
            
            <?php if(isset($deleted) && $deleted): ?>
                <div class="delete-notice" style="color:#34d399; border-color: rgba(52, 211, 153, 0.2); background: rgba(52, 211, 153, 0.1);">
                    <strong><i class="fas fa-shield-alt"></i> 安全提示：</strong><br>
                    为了防止系统被二次重置或恶意攻击，安装程序 <code>install.php</code> 已自动删除。
                </div>
            <?php elseif(isset($delete_error_message) && !empty($delete_error_message)): ?>
                <div class="delete-notice" style="color:#f87171; border-color: rgba(248, 113, 113, 0.2); background: rgba(248, 113, 113, 0.1);">
                    <strong><i class="fas fa-exclamation-triangle"></i> 重要警告：</strong><br>
                    <?php echo $delete_error_message; ?>
                </div>
            <?php endif; ?>

            <button class="btn-primary" onclick="window.location.href='cards.php'">进入后台管理</button>
        </div>
    <?php endif; ?>
</div>
</body>
</html>
