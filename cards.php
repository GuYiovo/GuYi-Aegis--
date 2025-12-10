<?php
require_once 'config.php';
require_once 'database.php';
session_start();

// --- 安全核心逻辑 ---

// 1. CSRF 令牌生成与验证
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

function verifyCSRF() {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        header('HTTP/1.1 403 Forbidden');
        die('Security Alert: CSRF Token Mismatch. Please refresh the page.');
    }
}

// 2. Cookie 签名验证 (HMAC-SHA256)
$is_trusted = false;
if (isset($_COOKIE['admin_trust'])) {
    $parts = explode('|', $_COOKIE['admin_trust']);
    if (count($parts) === 2) {
        list($payload, $sign) = $parts;
        if (hash_equals(hash_hmac('sha256', $payload, SYS_SECRET), $sign)) {
            $data = json_decode(base64_decode($payload), true);
            // 绑定 UserAgent 防止 Session 劫持
            if ($data && $data['exp'] > time() && $data['ua'] === md5($_SERVER['HTTP_USER_AGENT'])) {
                $is_trusted = true;
            }
        }
    }
}

// --- 业务逻辑 ---

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['batch_export'])) {
    verifyCSRF(); // 安全校验
    $db = new Database(); 
    $ids = $_POST['ids'] ?? [];
    if (empty($ids)) {
        echo "<script>alert('请先勾选需要导出的卡密'); history.back();</script>"; exit;
    }
    $data = $db->getCardsByIds($ids);
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="cards_export_'.date('YmdHis').'.txt"');
    echo "卡密 | 类型 | 状态 | 到期时间 | 备注\r\n";
    echo str_repeat("-", 80) . "\r\n";
    foreach ($data as $row) {
        // 状态显示逻辑更新：增加封禁判断
        if ($row['status'] == 2) {
            $status = '已封禁';
        } elseif ($row['status'] == 1) {
            $status = (strtotime($row['expire_time']) > time()) ? (empty($row['device_hash']) ? '待绑定' : '使用中') : '已过期';
        } else {
            $status = '未激活';
        }
        $type = CARD_TYPES[$row['card_type']]['name'] ?? $row['card_type'];
        echo "{$row['card_code']} | {$type} | {$status} | {$row['expire_time']} | {$row['notes']}\r\n";
    }
    exit;
}

$db = new Database();

if (isset($_GET['logout'])) { 
    session_destroy(); 
    setcookie('admin_trust', '', time() - 3600, '/'); 
    header('Location: cards.php'); 
    exit; 
}

// 自动登录
if (!isset($_SESSION['admin_logged_in']) && $is_trusted) {
    $_SESSION['admin_logged_in'] = true;
}

// 处理登录
if (!isset($_SESSION['admin_logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $error = null;
        // 验证码校验
        if (!$is_trusted) {
            $input_captcha = strtoupper($_POST['captcha'] ?? '');
            $sess_captcha = $_SESSION['captcha_code'] ?? 'INVALID';
            unset($_SESSION['captcha_code']);
            if (empty($input_captcha) || $input_captcha !== $sess_captcha) $error = "验证码错误或已过期";
        }

        if (!$error) {
            $hash = $db->getAdminHash();
            if (password_verify($_POST['password'], $hash)) {
                $_SESSION['admin_logged_in'] = true;
                // 设置强签名 Cookie
                $cookieData = ['exp' => time() + 86400 * 3, 'ua' => md5($_SERVER['HTTP_USER_AGENT'])];
                $payload = base64_encode(json_encode($cookieData));
                $sign = hash_hmac('sha256', $payload, SYS_SECRET);
                setcookie('admin_trust', "$payload|$sign", time() + 86400 * 3, '/', '', false, true); // HttpOnly
                header('Location: cards.php'); exit;
            } else {
                $error = "访问被拒绝：密钥无效";
            }
        }
        $login_error = $error;
    }
}

// --- 登录界面 (UI不变) ---
if (!isset($_SESSION['admin_logged_in'])): ?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统登录 - Enterprise Admin</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { margin:0; font-family:'Inter',sans-serif; background:#0f172a; height:100vh; display:flex; align-items:center; justify-content:center; overflow:hidden; }
        .bg-glow { position:absolute; width:600px; height:600px; background:radial-gradient(circle, rgba(56,189,248,0.15) 0%, rgba(0,0,0,0) 70%); top:50%; left:50%; transform:translate(-50%, -50%); pointer-events:none; }
        .login-box { position:relative; width:100%; max-width:400px; padding:40px; background:rgba(30,41,59,0.7); backdrop-filter:blur(20px); border:1px solid rgba(255,255,255,0.1); border-radius:16px; box-shadow:0 25px 50px -12px rgba(0,0,0,0.5); text-align:center; color:white; }
        .logo-img { width:64px; height:64px; border-radius:16px; margin:0 auto 20px; display:block; box-shadow:0 10px 15px -3px rgba(0,0,0,0.3); border: 2px solid rgba(255,255,255,0.1); }
        h1 { font-size:20px; margin:0 0 8px; font-weight:600; }
        p { color:#94a3b8; font-size:14px; margin:0 0 30px; }
        .input-group { margin-bottom: 20px; text-align: left; }
        input { width:100%; padding:12px 16px; background:rgba(0,0,0,0.2); border:1px solid rgba(255,255,255,0.1); border-radius:8px; color:white; font-size:14px; outline:none; transition:0.2s; box-sizing:border-box; }
        input:focus { border-color:#3b82f6; background:rgba(0,0,0,0.4); box-shadow:0 0 0 3px rgba(59,130,246,0.2); }
        button { width:100%; padding:12px; background:#3b82f6; border:none; border-radius:8px; color:white; font-weight:600; cursor:pointer; transition:0.2s; font-size:14px; }
        button:hover { background:#2563eb; transform:translateY(-1px); }
        .error { color:#ef4444; font-size:13px; margin-bottom:15px; background:rgba(239,68,68,0.1); padding:8px; border-radius:6px; }
        .captcha-row { display: flex; gap: 10px; }
        .captcha-img { border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); cursor: pointer; height: 43px; width: 100px; }
        .trust-badge { display: inline-block; font-size: 11px; background: rgba(16, 185, 129, 0.2); color: #34d399; padding: 2px 8px; border-radius: 10px; margin-bottom: 20px; border: 1px solid rgba(16, 185, 129, 0.3); }
    </style>
</head>
<body>
    <div class="bg-glow"></div>
    <div class="login-box">
        <img src="backend/logo.png" alt="Logo" class="logo-img">
        <h1>管理控制台</h1>
        <?php if($is_trusted): ?><div class="trust-badge">✓ 本机已通过安全验证</div><?php else: ?><p>Protected System Access</p><?php endif; ?>
        <?php if(isset($login_error)) echo "<div class='error'>{$login_error}</div>"; ?>
        <form method="POST">
            <div class="input-group"><input type="password" name="password" placeholder="请输入管理员密钥" required autofocus></div>
            <?php if(!$is_trusted): ?>
            <div class="input-group captcha-row">
                <input type="text" name="captcha" placeholder="验证码" maxlength="4" required autocomplete="off" style="text-align: center;">
                <img src="Verifyfile/captcha.php" class="captcha-img" onclick="this.src='Verifyfile/captcha.php?t='+Math.random()" title="点击刷新">
            </div>
            <?php endif; ?>
            <button type="submit">立即进入 &rarr;</button>
        </form>
    </div>
</body>
</html>
<?php exit; endif; ?>

<?php
// --- 后台操作处理 (所有操作必须验证 CSRF) ---
$tab = $_GET['tab'] ?? 'dashboard';
$msg = '';
$errorMsg = '';
$appList = $db->getApps();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCSRF(); // 全局 CSRF 验证

    if (isset($_POST['create_app'])) {
        try {
            $appName = trim($_POST['app_name']);
            if (empty($appName)) throw new Exception("应用名称不能为空");
            // 使用 htmlspecialchars 过滤输入
            $db->createApp(htmlspecialchars($appName), htmlspecialchars($_POST['app_notes']));
            $msg = "应用「".htmlspecialchars($appName)."」创建成功！";
            $appList = $db->getApps();
        } catch (Exception $e) { $errorMsg = $e->getMessage(); }
    } elseif (isset($_POST['toggle_app'])) {
        $db->toggleAppStatus($_POST['app_id']);
        $msg = "应用状态已更新";
        $appList = $db->getApps();
    } elseif (isset($_POST['delete_app'])) {
        try {
            $db->deleteApp($_POST['app_id']);
            $msg = "应用已删除";
            $appList = $db->getApps();
        } catch (Exception $e) { $errorMsg = $e->getMessage(); }
    }
    // 处理变量添加
    elseif (isset($_POST['add_var'])) {
        try {
            $varAppId = intval($_POST['var_app_id']);
            $varKey = trim($_POST['var_key']);
            $varVal = trim($_POST['var_value']);
            $varPub = isset($_POST['var_public']) ? 1 : 0;
            if (empty($varKey)) throw new Exception("变量名不能为空");
            $db->addAppVariable($varAppId, htmlspecialchars($varKey), htmlspecialchars($varVal), $varPub);
            $msg = "变量「".htmlspecialchars($varKey)."」添加成功";
        } catch (Exception $e) { $errorMsg = $e->getMessage(); }
    }
    // 处理变量删除
    elseif (isset($_POST['del_var'])) {
        $db->deleteAppVariable($_POST['var_id']);
        $msg = "变量已删除";
    }
    elseif (isset($_POST['batch_delete'])) {
        $count = $db->batchDeleteCards($_POST['ids'] ?? []);
        $msg = "已批量删除 {$count} 张卡密";
    } elseif (isset($_POST['batch_unbind'])) {
        $count = $db->batchUnbindCards($_POST['ids'] ?? []);
        $msg = "已批量解绑 {$count} 个设备";
    } elseif (isset($_POST['batch_add_time'])) {
        $hours = floatval($_POST['add_hours']);
        $count = $db->batchAddTime($_POST['ids'] ?? [], $hours);
        $msg = "已为 {$count} 张卡密增加 {$hours} 小时";
    }
    elseif (isset($_POST['gen_cards'])) {
        try {
            $targetAppId = intval($_POST['app_id']);
            $db->generateCards($_POST['num'], $_POST['type'], $_POST['pre'], '', 16, htmlspecialchars($_POST['note']), $targetAppId);
            $msg = "成功生成 {$_POST['num']} 张卡密";
        } catch (Exception $e) { $errorMsg = "生成失败: " . $e->getMessage(); }
    } elseif (isset($_POST['del_card'])) {
        $db->deleteCard($_POST['id']);
        $msg = "卡密已删除";
    } elseif (isset($_POST['unbind_card'])) {
        $res = $db->resetDeviceBindingByCardId($_POST['id']);
        $msg = $res ? "设备解绑成功" : "解绑失败";
    } elseif (isset($_POST['update_pwd'])) {
        $db->updateAdminPassword($_POST['new_pwd']);
        $msg = "管理员密码已更新";
    } 
    // --- 新增：卡密封禁/解封处理 ---
    elseif (isset($_POST['ban_card'])) {
        $db->updateCardStatus($_POST['id'], 2); // 2 = 封禁状态
        $msg = "卡密已封禁";
    } elseif (isset($_POST['unban_card'])) {
        $db->updateCardStatus($_POST['id'], 1); // 尝试恢复为正常
        $msg = "卡密已解除封禁";
    }
}

$dashboardData = $db->getDashboardData();
$cardList = isset($_GET['q']) ? $db->searchCards($_GET['q']) : $db->getAllCards();
$logs = $db->getUsageLogs(20, 0);
$activeDevices = $db->getActiveDevices();
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuYi Aegis Pro</title>
    <link rel="icon" href="backend/logo.png" type="image/png">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --sidebar-bg: #0f172a; --sidebar-text: #94a3b8; --sidebar-active: #3b82f6; --sidebar-hover: #1e293b;
            --body-bg: #f8fafc; --card-bg: #ffffff; --text-main: #1e293b; --text-muted: #64748b;
            --border: #e2e8f0; --primary: #3b82f6; --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
        }
        * { box-sizing: border-box; outline: none; }
        body { margin: 0; font-family: 'Inter', sans-serif; background: var(--body-bg); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        aside { width: 260px; background: var(--sidebar-bg); flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid #1e293b; }
        .brand { height: 64px; display: flex; align-items: center; padding: 0 24px; color: white; font-weight: 700; font-size: 16px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .brand-logo { width: 28px; height: 28px; border-radius: 6px; margin-right: 10px; border: 1px solid rgba(255,255,255,0.1); }
        .nav { flex: 1; padding: 24px 16px; overflow-y: auto; }
        .nav-label { font-size: 11px; text-transform: uppercase; color: #475569; font-weight: 700; margin: 0 0 8px 12px; letter-spacing: 0.5px; }
        .nav a { display: flex; align-items: center; padding: 10px 12px; color: var(--sidebar-text); text-decoration: none; border-radius: 8px; margin-bottom: 4px; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .nav a:hover { background: var(--sidebar-hover); color: white; }
        .nav a.active { background: var(--primary); color: white; box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
        .nav a i { width: 24px; margin-right: 8px; font-size: 16px; opacity: 0.8; }
        .user-panel { padding: 20px; border-top: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; gap: 12px; }
        .avatar-img { width: 36px; height: 36px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.1); object-fit: cover; }
        .user-info div { font-size: 13px; color: white; font-weight: 600; }
        .user-info span { font-size: 11px; color: #64748b; }
        .logout { margin-left: auto; color: #64748b; cursor: pointer; transition: 0.2s; }
        .logout:hover { color: var(--danger); }
        main { flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        header { height: 64px; background: var(--card-bg); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 32px; flex-shrink: 0; z-index: 10; }
        .title { font-size: 18px; font-weight: 600; color: var(--text-main); }
        .content { flex: 1; overflow-y: auto; padding: 32px; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 24px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.05); border-color: #cbd5e1; }
        .stat-label { color: var(--text-muted); font-size: 13px; font-weight: 500; display: flex; justify-content: space-between; align-items: center; }
        .stat-value { font-size: 28px; font-weight: 700; color: var(--text-main); margin-top: 8px; letter-spacing: -1px; }
        .stat-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
        .panel { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
        .panel-head { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #fdfdfd; }
        .panel-title { font-size: 15px; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; padding: 12px 24px; background: #f8fafc; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        td { padding: 16px 24px; border-bottom: 1px solid var(--border); color: var(--text-main); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #f1f5f9; }
        .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; line-height: 1; }
        .badge-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; background: currentColor; }
        .badge-success { background: #ecfdf5; color: #059669; }
        .badge-warn { background: #fffbeb; color: #d97706; }
        .badge-danger { background: #fef2f2; color: #dc2626; }
        .badge-neutral { background: #f1f5f9; color: #64748b; }
        .code { font-family: 'JetBrains Mono', monospace; background: #f1f5f9; padding: 4px 8px; border-radius: 6px; font-size: 12px; color: #0f172a; border: 1px solid #e2e8f0; }
        .btn { display: inline-flex; align-items: center; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: 0.2s; border: 1px solid transparent; text-decoration: none; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-danger { background: #fee2e2; color: #b91c1c; border-color: #fecaca; }
        .btn-warning { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
        .btn-secondary { background: #e2e8f0; color: #475569; }
        .btn-icon { padding: 8px; }
        .form-control { width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
        .toast { position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: white; padding: 12px 24px; border-radius: 8px; opacity: 0; transition: 0.3s; transform: translateY(20px); z-index: 100; font-size: 14px; }
        .toast.show { opacity: 1; transform: translateY(0); }
        .app-key-box { font-family: 'JetBrains Mono', monospace; background: #f1f5f9; padding: 8px 12px; border-radius: 6px; font-size: 12px; color: #475569; border: 1px solid #e2e8f0; word-break: break-all; display: flex; justify-content: space-between; align-items: center; }
        .app-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; background: #e0e7ff; color: #4338ca; font-size: 11px; font-weight: 600; margin-right: 8px; }
        
        /* 折叠面板样式 */
        details.panel > summary { list-style: none; cursor: pointer; transition: 0.2s; user-select: none; }
        details.panel > summary::-webkit-details-marker { display: none; }
        details.panel > summary:hover { background: #f8fafc; }
        details.panel[open] > summary { border-bottom: 1px solid var(--border); background: #fdfdfd; color: var(--primary); }
        details.panel > summary::after { content: '+'; float: right; font-weight: bold; }
        details.panel[open] > summary::after { content: '-'; }

        @media (max-width: 1024px) { .grid-4 { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) { aside { display: none; } .content { padding: 16px; } table { display: block; overflow-x: auto; white-space: nowrap; } }
        
        /* 公告动画效果 */
        .announcement-box {
            animation: slideDown 0.5s ease-out;
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
    </style>
</head>
<body>

<aside>
    <div class="brand"><img src="backend/logo.png" alt="Logo" class="brand-logo"> GuYi Aegis Pro <span style="font-size:10px; background:#3b82f6; padding:2px 6px; border-radius:4px; margin-left:8px;">Ent</span></div>
    <div class="nav">
        <div class="nav-label">概览</div>
        <a href="?tab=dashboard" class="<?=$tab=='dashboard'?'active':''?>"><i class="fas fa-chart-pie"></i> 仪表盘</a>
        <div class="nav-label">多租户</div>
        <a href="?tab=apps" class="<?=$tab=='apps'?'active':''?>"><i class="fas fa-cubes"></i> 应用接入</a>
        <div class="nav-label">业务</div>
        <a href="?tab=list" class="<?=$tab=='list'?'active':''?>"><i class="fas fa-database"></i> 卡密库存</a>
        <a href="?tab=create" class="<?=$tab=='create'?'active':''?>"><i class="fas fa-plus-circle"></i> 批量制卡</a>
        <div class="nav-label">监控</div>
        <a href="?tab=logs" class="<?=$tab=='logs'?'active':''?>"><i class="fas fa-history"></i> 审计日志</a>
        <a href="?tab=settings" class="<?=$tab=='settings'?'active':''?>"><i class="fas fa-cog"></i> 系统设置</a>
    </div>
    <div class="user-panel">
        <img src="backend/logo.png" alt="Admin" class="avatar-img">
        <div class="user-info"><div>Admin</div><span>Super User</span></div>
        <a href="?logout=1" class="logout"><i class="fas fa-sign-out-alt"></i></a>
    </div>
</aside>

<main>
    <header>
        <div class="title"><?php echo ['dashboard'=>'数据概览','apps'=>'应用管理','list'=>'卡密管理','create'=>'生产中心','logs'=>'日志审计','settings'=>'设置'][$tab]??'控制台'; ?></div>
        <?php if($msg): ?><div style="font-size:13px; color:var(--success); background:#ecfdf5; padding:6px 12px; border-radius:20px; font-weight:600;"><i class="fas fa-check-circle"></i> <?=$msg?></div><?php endif; ?>
        <?php if($errorMsg): ?><div style="font-size:13px; color:var(--danger); background:#fef2f2; padding:6px 12px; border-radius:20px; font-weight:600;"><i class="fas fa-exclamation-circle"></i> <?=$errorMsg?></div><?php endif; ?>
    </header>

    <div class="content">
        <?php if($tab == 'dashboard'): ?>
            <!-- 官方公告模块开始 -->
            <div class="panel announcement-box" style="background: linear-gradient(135deg, #eff6ff 0%, #ffffff 100%); border-left: 4px solid #3b82f6;">
                <div style="padding: 20px; display: flex; gap: 16px; align-items: flex-start;">
                    <div style="color: #3b82f6; font-size: 24px; padding-top: 2px;"><i class="fas fa-bullhorn"></i></div>
                    <div style="flex: 1;">
                        <div style="font-weight: 700; font-size: 16px; margin-bottom: 6px; color: #1e293b; display: flex; justify-content: space-between;">
                            <span>官方系统公告</span>
                            <span style="font-size: 11px; background: #3b82f6; color: white; padding: 2px 8px; border-radius: 10px; font-weight: 500;">NEW</span>
                        </div>
                        <div style="font-size: 14px; color: #475569; line-height: 1.6;">
                            欢迎使用 <b>GuYi Aegis Pro</b> 企业级验证管理系统。当前系统版本已更新至 V7.0。<br>
                            <ul style="margin: 5px 0 0 0; padding-left: 20px;">
                                <li>QQ群562807728</li>
                                <li>作者156440000</li>
                                <li>有bug可以进去反馈 <a href="?tab=logs" style="color:#3b82f6;text-decoration:none;font-weight:600;">审计日志</a> 检查异常访问记录。</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            <!-- 官方公告模块结束 -->

            <div class="grid-4">
                <div class="stat-card"><div class="stat-label">总库存量 <div class="stat-icon" style="background:#eff6ff; color:#3b82f6;"><i class="fas fa-layer-group"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['total']); ?></div></div>
                <div class="stat-card"><div class="stat-label">活跃设备 <div class="stat-icon" style="background:#ecfdf5; color:#10b981;"><i class="fas fa-wifi"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['active']); ?></div></div>
                <div class="stat-card"><div class="stat-label">接入应用 <div class="stat-icon" style="background:#ede9fe; color:#8b5cf6;"><i class="fas fa-cubes"></i></div></div><div class="stat-value"><?php echo count($appList) - (isset($appList[0]) && $appList[0]['id']==0 ? 1 : 0); ?></div></div>
                <div class="stat-card"><div class="stat-label">待售库存 <div class="stat-icon" style="background:#fffbeb; color:#d97706;"><i class="fas fa-tag"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['unused']); ?></div></div>
            </div>

            <div class="grid-4" style="grid-template-columns: 2fr 1fr;">
                 <div class="panel">
                    <div class="panel-head"><span class="panel-title">应用库存占比 (Top 5)</span></div>
                    <table>
                        <thead><tr><th>应用名称</th><th>卡密数</th><th>占比</th></tr></thead>
                        <tbody>
                            <?php 
                            $totalCards = $dashboardData['stats']['total'] > 0 ? $dashboardData['stats']['total'] : 1;
                            foreach($dashboardData['app_stats'] as $stat): 
                                if(empty($stat['app_name'])) continue; 
                                $percent = round(($stat['count'] / $totalCards) * 100, 1);
                            ?>
                            <tr>
                                <td style="font-weight:600;"><?php echo htmlspecialchars($stat['app_name']); ?></td>
                                <td><?php echo number_format($stat['count']); ?></td>
                                <td><div style="display:flex;align-items:center;gap:8px;"><div style="flex:1;height:6px;background:#f1f5f9;border-radius:3px;overflow:hidden;"><div style="width:<?=$percent?>%;height:100%;background:var(--primary);"></div></div><span style="font-size:12px;color:#64748b;width:36px;"><?=$percent?>%</span></div></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">类型分布</span></div>
                    <div style="height:200px;padding:20px;"><canvas id="typeChart"></canvas></div>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-head"><span class="panel-title">实时活跃设备监控</span><a href="?tab=list" class="btn btn-primary" style="font-size:12px; padding:6px 12px;">查看全部</a></div>
                <table>
                    <thead><tr><th>所属应用</th><th>卡密</th><th>设备指纹</th><th>激活时间</th><th>到期时间</th></tr></thead>
                    <tbody>
                        <?php foreach(array_slice($activeDevices, 0, 5) as $dev): ?>
                        <tr>
                            <td><?php if($dev['app_id']>0): ?><span class="app-tag"><?=htmlspecialchars($dev['app_name'])?></span><?php else: ?><span style="color:#94a3b8;font-size:12px;">未分类</span><?php endif; ?></td>
                            <td><span class="code"><?php echo $dev['card_code']; ?></span></td>
                            <td style="font-family:'JetBrains Mono'; font-size:12px; color:#64748b;"><?php echo substr($dev['device_hash'],0,12).'...'; ?></td>
                            <td><?php echo date('H:i', strtotime($dev['activate_time'])); ?></td>
                            <td><span class="badge badge-success"><?php echo date('m-d H:i', strtotime($dev['expire_time'])); ?></span></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <?php if($tab == 'apps'): ?>
            <?php 
            // 自动检测 API URL
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
            $currentScriptDir = dirname($_SERVER['SCRIPT_NAME']);
            $currentScriptDir = rtrim($currentScriptDir, '/'); // 移除末尾斜杠
            $apiUrl = $protocol . "://" . $_SERVER['HTTP_HOST'] . $currentScriptDir . "/Verifyfile/api.php";
            ?>

            <!-- 顶部切换按钮 -->
            <div style="margin-bottom: 20px; display: flex; gap: 10px;">
                <button onclick="switchAppView('apps')" id="btn_apps" class="btn btn-primary">应用列表</button>
                <button onclick="switchAppView('vars')" id="btn_vars" class="btn btn-secondary">变量管理</button>
            </div>

            <!-- 页面1：应用列表 -->
            <div id="view_apps">
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">已接入应用列表</span></div>
                    <table>
                        <thead><tr><th>应用名称</th><th>App Key (接口密钥)</th><th>卡密数</th><th>状态</th><th>操作</th></tr></thead>
                        <tbody>
                            <?php foreach($appList as $app): if($app['id'] == 0) continue; ?>
                            <tr>
                                <td><div style="font-weight:600;"><?=htmlspecialchars($app['app_name'])?></div><div style="font-size:11px;color:#94a3b8;">ID: <?=$app['id']?></div></td>
                                <td style="width:35%;"><div class="app-key-box"><span><?=$app['app_key']?></span><i class="fas fa-copy" style="cursor:pointer;color:#3b82f6;" onclick="copy('<?=$app['app_key']?>')"></i></div></td>
                                <td><span class="badge badge-neutral"><?=number_format($app['card_count'])?></span></td>
                                <td><?=$app['status']==1 ? '<span class="badge badge-success">正常</span>' : '<span class="badge badge-danger">禁用</span>'?></td>
                                <td>
                                    <button type="button" onclick="singleAction('toggle_app', <?=$app['id']?>)" class="btn <?=$app['status']==1?'btn-warning':'btn-primary'?> btn-icon"><i class="fas <?=$app['status']==1?'fa-ban':'fa-check'?>"></i></button>
                                    <button type="button" onclick="singleAction('delete_app', <?=$app['id']?>)" class="btn btn-danger btn-icon" <?=$app['card_count']>0?'disabled style="opacity:0.5"':''?>><i class="fas fa-trash"></i></button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                            <?php if(count($appList) <= 1): ?><tr><td colspan="5" style="text-align:center;padding:30px;color:#94a3b8;">暂无应用，请在下方创建</td></tr><?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <!-- API 信息 (折叠) -->
                <details class="panel">
                    <summary class="panel-head"><span class="panel-title">API 接口信息 (点击展开)</span></summary>
                    <div style="padding:24px;">
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">接口地址 (URL)</label>
                        <div class="app-key-box" style="margin-bottom:16px;">
                            <span style="font-size:11px;"><?php echo $apiUrl; ?></span>
                            <i class="fas fa-copy" style="cursor:pointer;color:#3b82f6;" onclick="copy('<?php echo $apiUrl; ?>')"></i>
                        </div>
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">JSON 请求示例</label>
                        <pre style="background:#f1f5f9; padding:10px; border-radius:6px; font-size:11px; font-family:'JetBrains Mono'; margin:0; border:1px solid #e2e8f0; color:#475569;">
{
  "key": "卡密代码 (可选)",
  "device": "设备机器码",
  "app_key": "上方对应Key"
}</pre>
                        <div style="font-size:11px;color:#64748b;margin-top:8px;">* 若仅传递 app_key 不传卡密，仅返回公开变量。</div>
                    </div>
                </details>

                <!-- 创建应用 (折叠) -->
                <details class="panel" open>
                    <summary class="panel-head"><span class="panel-title">创建新应用 (点击展开)</span></summary>
                    <div style="padding:24px;">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="create_app" value="1">
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">应用名称</label>
                            <input type="text" name="app_name" class="form-control" required placeholder="例如: 安卓客户端V1">
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">备注</label>
                            <textarea name="app_notes" class="form-control" style="height:80px;resize:none;"></textarea>
                            <div style="background:#f8fafc;padding:12px;border-radius:8px;font-size:12px;color:#64748b;margin-bottom:16px;border:1px solid #e2e8f0;">系统将自动生成 App Key，请妥善保管。</div>
                            <button type="submit" class="btn btn-primary" style="width:100%;">立即创建</button>
                        </form>
                    </div>
                </details>
            </div>

            <!-- 页面2：变量管理 -->
            <div id="view_vars" style="display:none;">
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">变量管理列表</span></div>
                    <table>
                        <thead><tr><th>所属应用</th><th>变量名 (Key)</th><th>值 (Value)</th><th>权限</th><th>操作</th></tr></thead>
                        <tbody>
                            <?php 
                            $hasVars = false;
                            foreach($appList as $app) {
                                if ($app['id'] == 0) continue;
                                $vars = $db->getAppVariables($app['id']);
                                foreach($vars as $v) {
                                    $hasVars = true;
                                    echo "<tr>";
                                    echo "<td><span class='app-tag'>".htmlspecialchars($app['app_name'])."</span></td>";
                                    echo "<td><span class='code'>".htmlspecialchars($v['key_name'])."</span></td>";
                                    echo "<td><div style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:#64748b;' title='".htmlspecialchars($v['value'])."'>".htmlspecialchars($v['value'])."</div></td>";
                                    echo "<td>".($v['is_public'] ? '<span class="badge badge-success">公开(免登)</span>' : '<span class="badge badge-warn">私有(需登录)</span>')."</td>";
                                    echo "<td><button type='button' onclick=\"singleAction('del_var', {$v['id']}, 'var_id')\" class='btn btn-danger btn-icon' title='删除变量'><i class='fas fa-trash'></i></button></td>";
                                    echo "</tr>";
                                }
                            }
                            if(!$hasVars) echo "<tr><td colspan='5' style='text-align:center;padding:20px;color:#94a3b8;'>暂无变量数据，请点击下方添加</td></tr>";
                            ?>
                        </tbody>
                    </table>
                </div>

                <!-- 添加变量 (折叠) -->
                <details class="panel" open>
                    <summary class="panel-head"><span class="panel-title">添加应用变量 (点击展开)</span></summary>
                    <div style="padding:24px;">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="add_var" value="1">
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">所属应用</label>
                            <select name="var_app_id" class="form-control" required>
                                <option value="">-- 请选择 --</option>
                                <?php foreach($appList as $app): if($app['id']==0) continue; ?>
                                    <option value="<?=$app['id']?>"><?=htmlspecialchars($app['app_name'])?></option>
                                <?php endforeach; ?>
                            </select>

                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">变量名 (Key)</label>
                            <input type="text" name="var_key" class="form-control" placeholder="例如: notice_msg" required>

                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">变量值 (Value)</label>
                            <textarea name="var_value" class="form-control" style="height:80px;resize:none;" placeholder="文本、JSON或脚本代码"></textarea>

                            <div style="margin-bottom:16px; display:flex; align-items:center;">
                                <input type="checkbox" id="var_public" name="var_public" value="1" style="width:auto;margin-right:8px;">
                                <label for="var_public" style="font-size:13px; font-weight:600; color:#475569;">公开变量 (无需登录即可读取)</label>
                            </div>

                            <button type="submit" class="btn btn-success" style="background:#10b981; border-color:#10b981; color:white; width:100%;">添加变量</button>
                        </form>
                    </div>
                </details>
            </div>
            
            <script>
                function switchAppView(view) {
                    const btnApps = document.getElementById('btn_apps');
                    const btnVars = document.getElementById('btn_vars');
                    const divApps = document.getElementById('view_apps');
                    const divVars = document.getElementById('view_vars');
                    
                    if (view === 'apps') {
                        btnApps.className = 'btn btn-primary';
                        btnVars.className = 'btn btn-secondary';
                        divApps.style.display = 'block';
                        divVars.style.display = 'none';
                    } else {
                        btnApps.className = 'btn btn-secondary';
                        btnVars.className = 'btn btn-primary';
                        divApps.style.display = 'none';
                        divVars.style.display = 'block';
                    }
                }
            </script>
        <?php endif; ?>

        <?php if($tab == 'list'): ?>
            <div class="panel">
                <form id="batchForm" method="POST">
                    <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                    <div class="panel-head">
                        <div style="display:flex;gap:10px;align-items:center;">
                            <input type="text" placeholder="搜索..." value="<?=$_GET['q']??''?>" class="form-control" style="margin:0;width:200px;" onkeydown="if(event.key==='Enter'){event.preventDefault();window.location='?tab=list&q='+this.value;}">
                            <a href="?tab=list" class="btn btn-icon" style="background:#f1f5f9;color:#64748b;"><i class="fas fa-sync"></i></a>
                            <div style="margin-left:10px;padding-left:10px;border-left:1px solid #e2e8f0;display:flex;gap:5px;">
                                <button type="submit" name="batch_export" value="1" class="btn" style="background:#6366f1;color:white;padding:8px 12px;font-size:12px;">导出</button>
                                <button type="button" onclick="submitBatch('batch_unbind')" class="btn" style="background:#f59e0b;color:white;padding:8px 12px;font-size:12px;">解绑</button>
                                <button type="button" onclick="batchAddTime()" class="btn" style="background:#10b981;color:white;padding:8px 12px;font-size:12px;">加时</button>
                                <button type="button" onclick="submitBatch('batch_delete')" class="btn btn-danger" style="padding:8px 12px;font-size:12px;">删除</button>
                            </div>
                        </div>
                        <a href="?tab=create" class="btn btn-primary">新建</a>
                    </div>
                    <input type="hidden" name="add_hours" id="addHoursInput">
                    <table>
                        <thead><tr><th style="width:40px;text-align:center;"><input type="checkbox" onclick="toggleAll(this)"></th><th>应用</th><th>卡密代码</th><th>类型</th><th>状态</th><th>备注</th><th>操作</th></tr></thead>
                        <tbody>
                            <?php foreach($cardList as $card): ?>
                            <tr>
                                <td style="text-align:center;"><input type="checkbox" name="ids[]" value="<?=$card['id']?>" class="row-check"></td>
                                <td><?php if($card['app_id']>0 && !empty($card['app_name'])): ?><span class="app-tag"><?=htmlspecialchars($card['app_name'])?></span><?php else: ?><span style="color:#94a3b8;font-size:12px;">未分类</span><?php endif; ?></td>
                                <td><span class="code" onclick="copy('<?=$card['card_code']?>')" style="cursor:pointer;"><?=$card['card_code']?></span></td>
                                <td><span style="font-weight:600;font-size:12px;"><?=CARD_TYPES[$card['card_type']]['name']??$card['card_type']?></span></td>
                                <td>
                                    <?php 
                                    if($card['status']==2): echo '<span class="badge badge-danger">已封禁</span>';
                                    elseif($card['status']==1): echo (strtotime($card['expire_time'])>time()) ? (empty($card['device_hash'])?'<span class="badge badge-warn">待绑定</span>':'<span class="badge badge-success">使用中</span>') : '<span class="badge badge-danger">已过期</span>'; 
                                    else: echo '<span class="badge badge-neutral">闲置</span>'; endif; 
                                    ?>
                                </td>
                                <td style="color:#94a3b8;font-size:12px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><?=htmlspecialchars($card['notes']?:'-')?></td>
                                <td style="display:flex;gap:8px;">
                                    <?php if($card['status']==1 && !empty($card['device_hash'])): ?><button type="button" onclick="singleAction('unbind_card', <?=$card['id']?>)" class="btn btn-warning btn-icon" title="解绑设备"><i class="fas fa-unlink"></i></button><?php endif; ?>
                                    
                                    <!-- 新增：封禁/解封按钮 -->
                                    <?php if($card['status']!=2): ?>
                                        <button type="button" onclick="singleAction('ban_card', <?=$card['id']?>)" class="btn btn-secondary btn-icon" title="封禁卡密" style="color:#ef4444;"><i class="fas fa-ban"></i></button>
                                    <?php else: ?>
                                        <button type="button" onclick="singleAction('unban_card', <?=$card['id']?>)" class="btn btn-secondary btn-icon" title="解除封禁" style="color:#10b981;"><i class="fas fa-unlock"></i></button>
                                    <?php endif; ?>
                                    
                                    <button type="button" onclick="singleAction('del_card', <?=$card['id']?>)" class="btn btn-danger btn-icon" title="删除"><i class="fas fa-trash"></i></button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </form>
            </div>
        <?php endif; ?>

        <?php if($tab == 'create'): ?>
            <div class="panel" style="max-width:600px; margin:0 auto;">
                <div class="panel-head"><span class="panel-title">批量生成卡密</span></div>
                <div style="padding:24px;">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                        <input type="hidden" name="gen_cards" value="1">
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;color:var(--primary);">归属应用 (必选)</label>
                        <select name="app_id" class="form-control" style="border-color:var(--primary);background:#eff6ff;" required>
                            <option value="">-- 请选择 --</option>
                            <?php foreach($appList as $app): if($app['id']==0 || $app['status']==0) continue; ?>
                                <option value="<?=$app['id']?>"><?=htmlspecialchars($app['app_name'])?></option>
                            <?php endforeach; ?>
                            <option value="0" style="color:#94a3b8;">[通用/未分类]</option>
                        </select>
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">生成数量</label>
                        <input type="number" name="num" class="form-control" value="10" min="1" max="500">
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">套餐类型</label>
                        <select name="type" class="form-control">
                            <?php foreach(CARD_TYPES as $k=>$v): ?><option value="<?=$k?>"><?=$v['name']?> (<?=$v['duration']>=86400?($v['duration']/86400).'天':($v['duration']/3600).'小时'?>)</option><?php endforeach; ?>
                        </select>
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">前缀 (选填)</label>
                        <input type="text" name="pre" class="form-control">
                        <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">备注</label>
                        <input type="text" name="note" class="form-control">
                        <button type="submit" class="btn btn-primary" style="width:100%;margin-top:16px;">确认生成</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <?php if($tab == 'logs'): ?>
            <div class="panel">
                <div class="panel-head"><span class="panel-title">鉴权日志 (最近20条)</span></div>
                <table>
                    <thead><tr><th>时间</th><th>来源</th><th>卡密</th><th>IP/设备</th><th>结果</th></tr></thead>
                    <tbody>
                        <?php foreach($logs as $log): ?>
                        <tr>
                            <td style="color:#64748b;font-size:12px;"><?=date('m-d H:i:s',strtotime($log['access_time']))?></td>
                            <td><?php if($log['app_name'] && $log['app_name']!=='System'): ?><span class="app-tag" style="font-size:10px;padding:2px 6px;"><?=htmlspecialchars($log['app_name'])?></span><?php else: ?><span style="color:#cbd5e1;font-size:11px;"><?=htmlspecialchars($log['app_name']?:'-')?></span><?php endif; ?></td>
                            <td><span class="code" style="font-size:11px;"><?=$log['card_code']?></span></td>
                            <td style="font-size:11px;"><div><?=$log['ip_address']?></div><div style="color:#94a3b8;font-family:'JetBrains Mono';font-size:10px;"><?=substr($log['device_hash'],0,8)?>...</div></td>
                            <td><?php $res=$log['result']; echo (strpos($res,'成功')!==false||strpos($res,'活跃')!==false)?'<span class="badge badge-success" style="font-size:10px;">'.$res.'</span>':((strpos($res,'失败')!==false||strpos($res,'过期')!==false||strpos($res,'封禁')!==false)?'<span class="badge badge-danger" style="font-size:10px;">'.$res.'</span>':'<span class="badge badge-neutral" style="font-size:10px;">'.$res.'</span>'); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <?php if($tab == 'settings'): ?>
            <div class="panel" style="max-width:500px;">
                <div class="panel-head"><span class="panel-title">修改管理员密码</span></div>
                <div style="padding:24px;">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                        <input type="hidden" name="update_pwd" value="1">
                        <input type="password" name="new_pwd" class="form-control" placeholder="设置新密码" required>
                        <button type="submit" class="btn btn-primary" style="width:100%;">更新密码</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
</main>

<div id="toast" class="toast"><i class="fas fa-check-circle" style="margin-right:8px; color:#4ade80;"></i> 已复制到剪贴板</div>

<script>
    function copy(text) { navigator.clipboard.writeText(text).then(() => { const t = document.getElementById('toast'); t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 2000); }); }
    function toggleAll(source) { document.querySelectorAll('.row-check').forEach(cb => cb.checked = source.checked); }
    function submitBatch(actionName) {
        if(document.querySelectorAll('.row-check:checked').length === 0) { alert('请先勾选需要操作的卡密'); return; }
        if(!confirm('确定要执行此批量操作吗？')) return;
        const form = document.getElementById('batchForm');
        const hidden = document.createElement('input'); hidden.type = 'hidden'; hidden.name = actionName; hidden.value = '1';
        form.appendChild(hidden); form.submit();
    }
    function batchAddTime() {
        if(document.querySelectorAll('.row-check:checked').length === 0) { alert('请先勾选需要操作的卡密'); return; }
        const hours = prompt("请输入要增加的小时数 (例如: 24)", "24");
        if(hours && !isNaN(hours)) { document.getElementById('addHoursInput').value = hours; submitBatch('batch_add_time'); }
    }
    function singleAction(actionName, id, idFieldName = 'id') {
        if(!confirm('确定执行此操作？')) return;
        const form = document.createElement('form'); form.method = 'POST'; form.style.display = 'none';
        
        const actInput = document.createElement('input'); actInput.name = actionName; actInput.value = '1';
        const idInput = document.createElement('input'); 
        
        // 特殊处理逻辑：如果是删除变量，ID 字段名为 var_id
        if(actionName === 'del_var') {
             idInput.name = 'var_id';
        } else if (actionName.includes('app')) {
             idInput.name = 'app_id';
        } else {
             idInput.name = 'id';
        }
        idInput.value = id;
        
        // 动态注入 CSRF Token
        const csrfInput = document.createElement('input'); csrfInput.name = 'csrf_token'; csrfInput.value = '<?=$csrf_token?>';
        
        form.appendChild(actInput); form.appendChild(idInput); form.appendChild(csrfInput);
        document.body.appendChild(form); form.submit();
    }

    <?php if($tab == 'dashboard'): ?>
    document.addEventListener("DOMContentLoaded", function() {
        const typeData = <?php echo json_encode($dashboardData['chart_types']); ?>;
        const cardTypes = <?php echo json_encode(CARD_TYPES); ?>;
        new Chart(document.getElementById('typeChart'), {
            type: 'doughnut',
            data: {
                labels: Object.keys(typeData).map(k => (cardTypes[k]?.name || k)),
                datasets: [{ data: Object.values(typeData), backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'], borderWidth: 0 }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'right', labels: { usePointStyle: true, boxWidth: 8, font: {size: 11} } } } }
        });
    });
    <?php endif; ?>
</script>
</body>
</html>
