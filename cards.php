<?php
// --- [防白屏核心] 强制开启错误提示，方便定位问题 ---
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
// ----------------------------------------------

require_once 'config.php';
require_once 'database.php';
session_start();

// --- [防白屏] 数据库连接异常捕获 ---
try {
    $db = new Database();
} catch (Throwable $e) {
    // [安全修复] 报错信息转义，防止潜在XSS
    die('<div style="font-family:sans-serif;text-align:center;padding:50px;">
        <h2 style="color:#ef4444;">系统连接失败</h2>
        <p>无法连接到数据库，原因如下：</p>
        <code style="background:#f1f5f9;padding:10px;display:block;margin:20px auto;max-width:600px;border-radius:5px;">'.htmlspecialchars($e->getMessage()).'</code>
        <p>请检查 config.php 配置或数据库服务状态。</p>
    </div>');
}

// 安全检查
if (defined('SYS_SECRET') && strpos(SYS_SECRET, 'ENT_SECure_K3y') !== false) {
    die('<div style="color:red;font-weight:bold;padding:20px;text-align:center;">安全警告：请立即修改 config.php 中的 SYS_SECRET 常量！<br>当前使用默认密钥极易被"一键进入后台"工具利用。</div>');
}

// --- [防白屏] CSRF 与 指纹初始化 ---
try {
    if (empty($_SESSION['csrf_token'])) {
        if (function_exists('random_bytes')) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $_SESSION['csrf_token'] = bin2hex(openssl_random_pseudo_bytes(32));
        } else {
            $_SESSION['csrf_token'] = md5(uniqid(mt_rand(), true));
        }
    }
    $csrf_token = $_SESSION['csrf_token'];

    $rawHash = $db->getAdminHash();
    $adminHashFingerprint = md5((string)$rawHash);

} catch (Throwable $e) {
    die("系统初始化异常: " . htmlspecialchars($e->getMessage()));
}

function verifyCSRF() {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'])) {
        header('HTTP/1.1 403 Forbidden');
        die('Security Alert: CSRF Token Mismatch. Please refresh the page.');
    }
}

$is_trusted = false;
if (isset($_COOKIE['admin_trust'])) {
    $parts = explode('|', $_COOKIE['admin_trust']);
    if (count($parts) === 2) {
        list($payload, $sign) = $parts;
        if (hash_equals(hash_hmac('sha256', $payload, SYS_SECRET), $sign)) {
            $data = json_decode(base64_decode($payload), true);
            if ($data && 
                isset($data['exp'], $data['ua'], $data['ph']) && 
                $data['exp'] > time() && 
                $data['ua'] === md5($_SERVER['HTTP_USER_AGENT']) &&
                hash_equals($data['ph'], $adminHashFingerprint)
            ) {
                $is_trusted = true;
            }
        }
    }
}

$appList = [];
try {
    $appList = $db->getApps(); 
} catch (Throwable $e) {
    $appList = []; 
    if(isset($_SESSION['admin_logged_in'])) $errorMsg = "应用列表加载异常: " . htmlspecialchars($e->getMessage());
}

// --- 业务逻辑 ---

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['batch_export'])) {
    verifyCSRF();
    if (!isset($_SESSION['admin_logged_in'])) die('Unauthorized');
    
    $ids = $_POST['ids'] ?? [];
    if (empty($ids)) {
        echo "<script>alert('请先勾选需要导出的卡密'); history.back();</script>"; exit;
    }
    $data = $db->getCardsByIds($ids);
    
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="cards_export_'.date('YmdHis').'.txt"');
    
    foreach ($data as $row) {
        echo "{$row['card_code']}\r\n";
    }
    exit;
}

if (isset($_GET['logout'])) { 
    session_destroy(); 
    setcookie('admin_trust', '', time() - 3600, '/'); 
    header('Location: cards.php'); 
    exit; 
}

if (!isset($_SESSION['admin_logged_in']) && $is_trusted) {
    $_SESSION['admin_logged_in'] = true;
    // [安全修复] 自动登录也需要重置Session ID
    session_regenerate_id(true);
    $_SESSION['last_ip'] = $_SERVER['REMOTE_ADDR'];
}

if (isset($_SESSION['admin_logged_in']) && isset($_SESSION['last_ip']) && $_SESSION['last_ip'] !== $_SERVER['REMOTE_ADDR']) {
    session_unset();
    session_destroy();
    header('Location: cards.php');
    exit;
}

if (!isset($_SESSION['admin_logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        $error = null;
        if (!$is_trusted) {
            $input_captcha = strtoupper($_POST['captcha'] ?? '');
            $sess_captcha = $_SESSION['captcha_code'] ?? 'INVALID';
            unset($_SESSION['captcha_code']);
            if (empty($input_captcha) || $input_captcha !== $sess_captcha) $error = "验证码错误或已过期";
        }

        if (!$error) {
            $hash = $db->getAdminHash();
            if (!empty($hash) && password_verify($_POST['password'], $hash)) {
                // [安全修复] 防止会话固定攻击
                session_regenerate_id(true);
                
                $_SESSION['admin_logged_in'] = true;
                $_SESSION['last_ip'] = $_SERVER['REMOTE_ADDR'];
                
                $cookieData = [
                    'exp' => time() + 86400 * 3, 
                    'ua' => md5($_SERVER['HTTP_USER_AGENT']),
                    'ph' => md5($hash)
                ];
                $payload = base64_encode(json_encode($cookieData));
                $sign = hash_hmac('sha256', $payload, SYS_SECRET);
                setcookie('admin_trust', "$payload|$sign", time() + 86400 * 3, '/', '', false, true);
                
                header('Location: cards.php'); exit;
            } else {
                usleep(500000); 
                $error = "访问被拒绝：密钥无效";
            }
        }
        $login_error = $error;
    }
}

if (!isset($_SESSION['admin_logged_in'])): 
    // 检测是否为移动端
    $is_mobile = preg_match("/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|mobi|palm|phone|pie|samsung|scp|wap|windows ce;iemobile|xhtml\\+xml)/i", $_SERVER["HTTP_USER_AGENT"]);
    // 根据设备选择背景图
    $bg_img = $is_mobile ? 'backend/pjt.png' : 'backend/pcpjt.png';
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>登录 - GuYi Admin</title>
    <!-- 已加回 Favicon -->
    <link rel="icon" href="backend/logo.png" type="image/png">
    <style>
        /* --- auth.css 内容嵌入 --- */
        :root {
            --ay-accent-start: #ff7dc6; /* 霓虹起色 */
            --ay-accent-end: #7aa8ff; /* 霓虹终色 */
            --ay-text: #f3f6ff; /* 主文字 */
            --ay-sub: #b9c3e6; /* 次文字 */
            --ay-card: rgba(12, 14, 28, .55); /* 卡片深玻璃 */
            --ay-stroke: rgba(255, 255, 255, .18); /* 细边 */
            --ay-input: rgba(255, 255, 255, .06); /* 输入框底 */
            --ay-input-h: 48px; /* 输入高度 */
            --ay-radius: 20px; /* 圆角 */
        }

        html, body { height: 100%; }
        *, *::before, *::after { box-sizing: border-box; }

        body.ay-bg {
            margin: 0;
            color: var(--ay-text);
            font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, PingFang SC, Microsoft YaHei, system-ui, Arial;
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            overflow-x: hidden;
        }

        .ay-dim {
            position: fixed; inset: 0; pointer-events: none;
            background: radial-gradient(60% 50% at 50% 30%, rgba(0, 0, 0, .25), rgba(0, 0, 0, .55) 70%);
        }

        .ay-petals { position: fixed; inset: 0; pointer-events: none; overflow: hidden; }
        .ay-petals i {
            position: absolute; width: 12px; height: 10px;
            background: linear-gradient(135deg, #ffd1e6, #ff9aca);
            border-radius: 80% 80% 80% 20% / 80% 80% 20% 80%;
            opacity: .5; filter: blur(.2px);
            animation: ay-fall linear infinite; transform: rotate(20deg);
        }
        .ay-petals i:nth-child(3n) { width: 9px; height: 7px; animation-duration: 12s; }
        .ay-petals i:nth-child(4n) { animation-duration: 10s; opacity: .35; }
        .ay-petals i:nth-child(5n) { width: 14px; height: 12px; animation-duration: 14s; }
        @keyframes ay-fall { to { transform: translateY(110vh) rotate(360deg); } }

        .ay-wrap {
            min-height: 100dvh; display: grid; place-items: center;
            padding: clamp(16px, 4vw, 32px); perspective: 1000px;
        }

        .ay-card {
            width: min(480px, 92vw); margin-top: 14px;
            background: var(--ay-card); backdrop-filter: blur(16px) saturate(140%);
            border: 1px solid var(--ay-stroke); border-radius: 24px;
            box-shadow: 0 18px 60px rgba(5, 9, 20, .45);
            position: relative; overflow: hidden; transform-style: preserve-3d;
            transition: box-shadow .25s ease; will-change: transform;
        }
        .ay-card:hover { box-shadow: 0 24px 80px rgba(5,9,20,.55); }
        .ay-card::after{
            content:""; position:absolute; inset:-1px; border-radius:inherit; pointer-events:none; mix-blend-mode:overlay; opacity:0; transition: opacity .3s ease;
            background: radial-gradient(300px 300px at var(--mx, 50%) var(--my, 50%), rgba(255,255,255,.15), rgba(255,255,255,0) 60%); z-index: 10;
        }
        .ay-card:hover::after{ opacity:1; }
        .ay-card::before {
            content: ""; position: absolute; inset: -1px; border-radius: inherit; padding: 1px;
            background: conic-gradient(from 200deg, var(--ay-accent-start), var(--ay-accent-end), var(--ay-accent-start));
            -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
            -webkit-mask-composite: xor; mask-composite: exclude;
            opacity: .7; pointer-events: none;
        }

        .ay-head { padding: 26px 22px 8px; display: grid; place-items: center; row-gap: 8px; }
        .ay-logo {
            width: 64px; height: 64px; border-radius: 50%;
            background: url("backend/logo.png") no-repeat center/contain;
            box-shadow: 0 8px 26px rgba(255, 154, 202, .25);
        }
        .ay-title { margin: 4px 0 0; font-weight: 900; letter-spacing: .6px; font-size: clamp(18px, 2.6vw, 22px); color: white; }
        .ay-sub { margin: 0 0 6px; color: var(--ay-sub); font-size: 12px; text-align: center; }

        .ay-body { padding: 16px 22px 22px; }
        .ay-field { position: relative; margin: 16px 0 22px; }
        .ay-input {
            width: 100%; height: var(--ay-input-h); padding: 12px 14px; border-radius: 16px;
            border: 1px solid var(--ay-stroke); background: var(--ay-input); color: var(--ay-text);
            outline: none; transition: all .18s ease;
        }
        .ay-input:-webkit-autofill {
            -webkit-text-fill-color: var(--ay-text) !important;
            transition: background-color 5000s ease-in-out 0s;
            box-shadow: inset 0 0 0 1000px rgba(255, 255, 255, 0.06) !important;
        }
        .ay-input::placeholder { color: transparent; }
        .ay-label {
            position: absolute; left: 14px; top: 50%; transform: translateY(-52%);
            font-size: 13px; color: var(--ay-sub); pointer-events: none;
            transition: all .2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .ay-input:focus {
            border-color: rgba(255, 255, 255, .38);
            box-shadow: 0 0 0 3px rgba(255, 125, 198, .18);
            background: rgba(255, 255, 255, .08);
        }
        .ay-input:focus + .ay-label, .ay-input:not(:placeholder-shown) + .ay-label {
            top: -9px; font-size: 11px; background: rgba(10, 12, 24, .95);
            padding: 0 8px; border-radius: 999px; color: #e9eaff;
            border: 1px solid rgba(255, 255, 255, .15); transform: translateY(0);
        }

        .ay-eye {
            position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
            width: 34px; height: 34px; border-radius: 10px; border: 1px solid transparent;
            background: transparent; display: grid; place-items: center; cursor: pointer; transition: background .2s;
        }
        .ay-eye:hover { background: rgba(255,255,255,0.1); }
        .ay-eye svg { transition: stroke .3s ease; }

        /* 验证码图片样式 */
        .ay-captcha-img {
            position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
            height: 36px; border-radius: 10px; cursor: pointer;
            border: 1px solid rgba(255,255,255,0.1); opacity: 0.85; transition: opacity .2s;
        }
        .ay-captcha-img:hover { opacity: 1; }

        .ay-btn {
            width: 100%; height: 48px; border: none; border-radius: 14px; cursor: pointer;
            color: #ffffff; font-weight: 900; letter-spacing: .5px; margin-top: 10px;
            background: linear-gradient(135deg, #ffb6f0, #9ad6ff);
            box-shadow: 0 12px 30px rgba(122, 168, 255, .35), inset 0 1px 0 rgba(255, 255, 255, .7);
            position: relative; overflow: hidden; transition: transform .1s ease, box-shadow .2s ease, filter .2s;
        }
        .ay-btn:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 16px 36px rgba(122,168,255,.45), inset 0 1px 0 rgba(255,255,255,.8); 
        }
        .ay-btn:active { 
            transform: translateY(1px) scale(0.98); filter: brightness(0.95);
        }
        .ay-btn::after{ 
            content:""; position:absolute; top:-20%; bottom:-20%; left:-40%; right:-40%; pointer-events:none;
            background: linear-gradient(90deg, rgba(255,255,255,0) 0%, rgba(255,255,255,.4) 50%, rgba(255,255,255,0) 100%);
            transform: translateX(-120%) skewX(-20deg); transition: transform .6s ease;
        }
        .ay-btn:hover::after{ transform: translateX(140%) skewX(-20deg); }

        .ay-foot { margin: 12px 0 8px; text-align: center; color: #dfe6ff; font-size: 12px; opacity: .7; transition: opacity .2s; }
        .ay-foot:hover { opacity: 1; }
        
        .ay-error {
            background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5; font-size: 12px; padding: 8px 12px; border-radius: 12px;
            margin-bottom: 12px; display: flex; align-items: center; gap: 6px;
        }

        @media (max-width: 480px) {
            :root { --ay-input-h: 46px; }
            .ay-body { padding: 12px 16px 18px; }
            .ay-card { transform: none !important; }
        }
    </style>
</head>
<body class="ay-bg">
<script>
    // 离线模式：智能检测设备并设置壁纸
    (function(){
        var bgUrl = '<?php echo $bg_img; ?>';
        var gradient = 'linear-gradient(180deg, rgb(255 255 255 / 0%), rgb(255 255 255 / 71%))';
        document.body.style.backgroundImage = gradient + ", url('" + bgUrl + "')";
    })();
</script>

<div class="ay-dim" aria-hidden="true"></div>
<div class="ay-petals" aria-hidden="true">
    <i style="left:6%; top:-8vh; animation-duration:11s"></i>
    <i style="left:24%; top:-12vh; animation-duration:13s"></i>
    <i style="left:52%; top:-16vh; animation-duration:12s"></i>
    <i style="left:72%; top:-10vh; animation-duration:10s"></i>
    <i style="left:86%; top:-18vh; animation-duration:14s"></i>
</div>

<main class="ay-wrap">
    <section class="ay-card" id="ay-card" role="dialog" aria-labelledby="ay-title" aria-describedby="ay-sub">
        <header class="ay-head">
            <div class="ay-logo" aria-hidden="true"></div>
            <h1 id="ay-title" class="ay-title">欢迎回来，指挥官</h1>
            <p id="ay-sub" class="ay-sub">正在验证您的管理员身份</p>
        </header>

        <div class="ay-body">
            <?php if(isset($login_error)): ?>
                <div class="ay-error">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    <?php echo $login_error; ?>
                </div>
            <?php endif; ?>

            <form id="ay-form" method="POST">
                <!-- 管理员密钥输入 (原邮箱) -->
                <div class="ay-field">
                    <input id="ay-user" name="password" class="ay-input" type="password" placeholder=" "
                           autocomplete="current-password" required style="padding-right: 44px;">
                    <span class="ay-label">管理员密钥</span>
                    <button type="button" class="ay-eye" id="ay-eye" aria-label="显示密钥">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#cfe1ff" stroke-width="2"
                             stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12Z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                    </button>
                </div>

                <!-- 验证码输入 (原密码) -->
                <?php if(!$is_trusted): ?>
                <div class="ay-field">
                    <input id="ay-captcha" name="captcha" class="ay-input" type="text" placeholder=" "
                           autocomplete="off" required maxlength="4" style="padding-right: 120px;">
                    <span class="ay-label">验证码</span>
                    <img src="Verifyfile/captcha.php" class="ay-captcha-img" onclick="this.src='Verifyfile/captcha.php?t='+Math.random()" title="点击刷新">
                </div>
                <?php endif; ?>

                <button class="ay-btn" type="submit" id="ay-submit">立即进入</button>
            </form>
            <div class="ay-foot">© GuYi Aegis Pro System</div>
        </div>
    </section>
</main>

<script>
    // 交互优化脚本
    document.addEventListener('DOMContentLoaded', () => {
        // 1. 密钥显示/隐藏切换
        const passInput = document.getElementById('ay-user');
        const eyeBtn = document.getElementById('ay-eye');
        if(eyeBtn && passInput) {
            const eyeIcon = eyeBtn.querySelector('svg');
            eyeBtn.addEventListener('click', () => {
                const isPassword = passInput.type === 'password';
                passInput.type = isPassword ? 'text' : 'password';
                eyeIcon.style.stroke = isPassword ? '#ff7dc6' : '#cfe1ff';
            });
        }

        // 2. 卡片 3D 视差与光照追踪效果
        const card = document.getElementById('ay-card');
        const wrap = document.querySelector('.ay-wrap');

        wrap.addEventListener('mousemove', (e) => {
            if (window.innerWidth <= 768) return; // 移动端禁用

            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            // 设置光标位置变量，用于CSS光照
            card.style.setProperty('--mx', `${x}px`);
            card.style.setProperty('--my', `${y}px`);

            // 计算旋转角度 (轻微视差)
            const rotateX = ((e.clientY - window.innerHeight / 2) / window.innerHeight) * -4;
            const rotateY = ((e.clientX - window.innerWidth / 2) / window.innerWidth) * 4;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });

        // 鼠标离开复位
        wrap.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
            card.style.setProperty('--mx', '50%');
            card.style.setProperty('--my', '50%');
        });
    });
</script>
</body>
</html>
<?php exit; endif; ?>

<?php
// --- 后台操作处理 ---
$tab = $_GET['tab'] ?? 'dashboard';
// 定义页面标题映射，用于面包屑和标签显示
$pageTitles = [
    'dashboard' => '首页',
    'apps' => '应用管理',
    'list' => '单码管理',
    'create' => '批量制卡',
    'logs' => '审计日志',
    'settings' => '系统配置'
];
$currentTitle = $pageTitles[$tab] ?? '控制台';

$msg = '';
if(!isset($errorMsg)) $errorMsg = ''; 

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verifyCSRF();

    if (isset($_POST['create_app'])) {
        try {
            $appName = trim($_POST['app_name']);
            if (empty($appName)) throw new Exception("应用名称不能为空");
            $db->createApp(htmlspecialchars($appName), htmlspecialchars($_POST['app_version'] ?? ''), htmlspecialchars($_POST['app_notes']));
            $msg = "应用「".htmlspecialchars($appName)."」创建成功！";
            $appList = $db->getApps();
        } catch (Exception $e) { $errorMsg = htmlspecialchars($e->getMessage()); }
    } elseif (isset($_POST['toggle_app'])) {
        $db->toggleAppStatus($_POST['app_id']);
        $msg = "应用状态已更新";
        $appList = $db->getApps();
    } elseif (isset($_POST['delete_app'])) {
        try {
            $db->deleteApp($_POST['app_id']);
            $msg = "应用已删除";
            $appList = $db->getApps();
        } catch (Exception $e) { $errorMsg = htmlspecialchars($e->getMessage()); }
    } elseif (isset($_POST['edit_app'])) { 
        try {
            $appId = intval($_POST['app_id']);
            $appName = trim($_POST['app_name']);
            if (empty($appName)) throw new Exception("应用名称不能为空");
            $db->updateApp($appId, htmlspecialchars($appName), htmlspecialchars($_POST['app_version'] ?? ''), htmlspecialchars($_POST['app_notes']));
            $msg = "应用信息已更新";
            $appList = $db->getApps();
        } catch (Exception $e) { $errorMsg = htmlspecialchars($e->getMessage()); }
    }
    elseif (isset($_POST['add_var'])) {
        try {
            $varAppId = intval($_POST['var_app_id']);
            $varKey = trim($_POST['var_key']);
            $varVal = trim($_POST['var_value']);
            $varPub = isset($_POST['var_public']) ? 1 : 0;
            if (empty($varKey)) throw new Exception("变量名不能为空");
            $db->addAppVariable($varAppId, htmlspecialchars($varKey), htmlspecialchars($varVal), $varPub);
            $msg = "变量「".htmlspecialchars($varKey)."」添加成功";
        } catch (Exception $e) { $errorMsg = htmlspecialchars($e->getMessage()); }
    }
    elseif (isset($_POST['edit_var'])) {
        try {
            $varId = intval($_POST['var_id']);
            $varKey = trim($_POST['var_key']);
            $varVal = trim($_POST['var_value']);
            $varPub = isset($_POST['var_public']) ? 1 : 0;
            if (empty($varKey)) throw new Exception("变量名不能为空");
            $db->updateAppVariable($varId, htmlspecialchars($varKey), htmlspecialchars($varVal), $varPub);
            $msg = "变量更新成功";
        } catch (Exception $e) { $errorMsg = htmlspecialchars($e->getMessage()); }
    }
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
        } catch (Exception $e) { $errorMsg = "生成失败: " . htmlspecialchars($e->getMessage()); }
    } elseif (isset($_POST['del_card'])) {
        $db->deleteCard($_POST['id']);
        $msg = "卡密已删除";
    } elseif (isset($_POST['unbind_card'])) {
        $res = $db->resetDeviceBindingByCardId($_POST['id']);
        $msg = $res ? "设备解绑成功" : "解绑失败";
    } 
    elseif (isset($_POST['update_pwd'])) {
        $pwd1 = $_POST['new_pwd'] ?? '';
        $pwd2 = $_POST['confirm_pwd'] ?? '';
        
        if (empty($pwd1)) {
            $errorMsg = "密码不能为空";
        } elseif ($pwd1 !== $pwd2) {
            $errorMsg = "两次输入的密码不一致，请重试";
        } else {
            $db->updateAdminPassword($pwd1);
            setcookie('admin_trust', '', time() - 3600, '/');
            $msg = "管理员密码已更新，所有已登录的设备需重新登录";
        }
    } 
    elseif (isset($_POST['ban_card'])) {
        $db->updateCardStatus($_POST['id'], 2);
        $msg = "卡密已封禁";
    } elseif (isset($_POST['unban_card'])) {
        $db->updateCardStatus($_POST['id'], 1);
        $msg = "卡密已解除封禁";
    }
}

$dashboardData = ['stats'=>['total'=>0,'unused'=>0,'active'=>0], 'app_stats'=>[], 'chart_types'=>[]];
$logs = [];
$activeDevices = [];
$cardList = [];
$totalCards = 0;
$totalPages = 0;

try {
    $dashboardData = $db->getDashboardData();
} catch (Throwable $e) { $errorMsg .= " 仪表盘数据加载失败"; }

try {
    $logs = $db->getUsageLogs(20, 0);
} catch (Throwable $e) { }

try {
    $activeDevices = $db->getActiveDevices();
} catch (Throwable $e) { }

// 分页逻辑
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = isset($_GET['limit']) ? intval($_GET['limit']) : 20; 
if ($perPage < 5) $perPage = 20;
if ($perPage > 500) $perPage = 500;

$statusFilter = null;
$filterStr = $_GET['filter'] ?? 'all';
if ($filterStr === 'unused') $statusFilter = 0;
elseif ($filterStr === 'active') $statusFilter = 1;
elseif ($filterStr === 'banned') $statusFilter = 2;

// [修改] 获取应用ID，如果没有选择应用，则不加载卡密
$appFilter = isset($_GET['app_id']) && $_GET['app_id'] !== '' ? intval($_GET['app_id']) : null;
$isSearching = isset($_GET['q']) && !empty($_GET['q']);

$offset = ($page - 1) * $perPage;

try {
    if ($isSearching) {
        // 如果正在搜索，则不受应用筛选限制，显示搜索结果
        $allResults = $db->searchCards($_GET['q']);
        $totalCards = count($allResults);
        $cardList = array_slice($allResults, $offset, $perPage);
    } elseif ($appFilter !== null) {
        // [关键逻辑] 只有当选择了应用时，才去数据库查询卡密
        $totalCards = $db->getTotalCardCount($statusFilter, $appFilter);
        $cardList = $db->getCardsPaginated($perPage, $offset, $statusFilter, $appFilter);
    } else {
        // [关键逻辑] 未选择应用，数据为空
        $totalCards = 0;
        $cardList = [];
    }
} catch (Throwable $e) { $errorMsg .= " 卡密列表加载失败: " . htmlspecialchars($e->getMessage()); }

$totalPages = ceil($totalCards / $perPage);
if ($totalPages > 0 && $page > $totalPages) { $page = $totalPages; }

?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>GuYi Aegis Pro</title>
    <link rel="icon" href="backend/logo.png" type="image/png">
    
    <link href="assets/css/all.min.css" rel="stylesheet">
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    
    <script src="assets/js/chart.js"></script>

    <style>
        :root {
            --sidebar-bg: #0f172a; --sidebar-text: #94a3b8; --sidebar-active: #3b82f6; --sidebar-hover: #1e293b;
            --body-bg: #f8fafc; --card-bg: #ffffff; --text-main: #1e293b; --text-muted: #64748b;
            --border: #e2e8f0; --primary: #3b82f6; --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
        }
        * { box-sizing: border-box; outline: none; -webkit-tap-highlight-color: transparent; }
        body { margin: 0; font-family: 'Inter', sans-serif; background: var(--body-bg); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        aside { width: 260px; background: var(--sidebar-bg); flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid #1e293b; transition: transform 0.3s ease; z-index: 1000; }
        .brand { height: 64px; display: flex; align-items: center; padding: 0 24px; color: white; font-weight: 700; font-size: 16px; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .brand-logo { width: 28px; height: 28px; border-radius: 6px; margin-right: 10px; border: 1px solid rgba(255,255,255,0.1); }
        .nav { flex: 1; padding: 24px 16px; overflow-y: auto; }
        .nav-label { font-size: 11px; text-transform: uppercase; color: #475569; font-weight: 700; margin: 0 0 8px 12px; letter-spacing: 0.5px; }
        .nav a { display: flex; align-items: center; padding: 12px; color: var(--sidebar-text); text-decoration: none; border-radius: 8px; margin-bottom: 4px; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .nav a:hover { background: var(--sidebar-hover); color: white; }
        .nav a.active { background: var(--primary); color: white; box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
        .nav a i { width: 24px; margin-right: 8px; font-size: 16px; opacity: 0.8; }
        .user-panel { padding: 20px; border-top: 1px solid rgba(255,255,255,0.05); display: flex; align-items: center; gap: 12px; background: #0b1120; }
        .avatar-img { width: 36px; height: 36px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.1); object-fit: cover; }
        .user-info div { font-size: 13px; color: white; font-weight: 600; }
        .user-info span { font-size: 11px; color: #64748b; }
        .logout { margin-left: auto; color: #64748b; cursor: pointer; transition: 0.2s; padding: 8px; }
        .logout:hover { color: var(--danger); }
        main { flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        header { height: 64px; background: var(--card-bg); border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; padding: 0 20px; flex-shrink: 0; z-index: 10; }
        .title { font-size: 18px; font-weight: 600; color: var(--text-main); }
        .content { flex: 1; overflow-y: auto; padding: 24px; -webkit-overflow-scrolling: touch; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 24px; }
        .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.05); border-color: #cbd5e1; }
        .stat-label { color: var(--text-muted); font-size: 13px; font-weight: 500; display: flex; justify-content: space-between; align-items: center; }
        .stat-value { font-size: 28px; font-weight: 700; color: var(--text-main); margin-top: 8px; letter-spacing: -1px; }
        .stat-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
        .panel { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
        .panel-head { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #fdfdfd; flex-wrap: wrap; gap: 10px; }
        .panel-title { font-size: 15px; font-weight: 600; }
        .table-responsive { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; white-space: nowrap; }
        th { text-align: left; padding: 12px 20px; background: #f8fafc; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        td { padding: 16px 20px; border-bottom: 1px solid var(--border); color: var(--text-main); vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #f1f5f9; }
        .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; line-height: 1; }
        .badge-dot { width: 6px; height: 6px; border-radius: 50%; margin-right: 6px; background: currentColor; }
        .badge-success { background: #ecfdf5; color: #059669; }
        .badge-warn { background: #fffbeb; color: #d97706; }
        .badge-danger { background: #fef2f2; color: #dc2626; }
        .badge-neutral { background: #f1f5f9; color: #64748b; }
        .badge-primary { background: #eff6ff; color: #3b82f6; }
        .code { font-family: 'JetBrains Mono', monospace; background: #f1f5f9; padding: 4px 8px; border-radius: 6px; font-size: 12px; color: #0f172a; border: 1px solid #e2e8f0; }
        .btn { display: inline-flex; align-items: center; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: 0.2s; border: 1px solid transparent; text-decoration: none; justify-content: center; }
        .btn-primary { background: var(--primary); color: white; }
        .btn-danger { background: #fee2e2; color: #b91c1c; border-color: #fecaca; }
        .btn-warning { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
        .btn-secondary { background: #e2e8f0; color: #475569; }
        .btn-icon { padding: 8px; min-width: 32px; }
        .form-control { width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 16px; font-size: 14px; -webkit-appearance: none; }
        .toast { position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: white; padding: 12px 24px; border-radius: 8px; opacity: 0; transition: 0.3s; transform: translateY(20px); z-index: 2000; font-size: 14px; }
        .toast.show { opacity: 1; transform: translateY(0); }
        .app-key-box { font-family: 'JetBrains Mono', monospace; background: #f8fafc; padding: 6px 10px; border-radius: 6px; font-size: 11px; color: #475569; border: 1px solid #e2e8f0; word-break: break-all; display: inline-flex; align-items: center; gap: 8px; }
        .app-tag { display: inline-block; padding: 2px 8px; border-radius: 4px; background: #e0e7ff; color: #4338ca; font-size: 11px; font-weight: 600; margin-right: 8px; }
        .nav-segment { background: #fff; padding: 4px; border-radius: 8px; display: inline-flex; border: 1px solid var(--border); margin-bottom: 24px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); width: 100%; overflow-x: auto; }
        .nav-pill { padding: 8px 20px; border-radius: 6px; font-size: 13px; font-weight: 600; color: var(--text-muted); background: transparent; border: none; cursor: pointer; transition: all 0.2s; white-space: nowrap; text-decoration: none; display: inline-block; text-align: center; flex: 1;}
        .nav-pill:hover { color: var(--text-main); }
        .nav-pill.active { background: var(--primary); color: white; box-shadow: 0 2px 4px rgba(59,130,246,0.3); }
        .pagination { display: flex; align-items: center; justify-content: center; gap: 6px; padding: 20px; border-top: 1px solid var(--border); flex-wrap: wrap; }
        .page-select { padding: 6px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; color: var(--text-main); background: white; outline: none; margin-right: auto; }
        .page-btn { display: inline-flex; align-items: center; justify-content: center; min-width: 32px; height: 32px; padding: 0 8px; background: white; border: 1px solid var(--border); border-radius: 6px; color: var(--text-main); text-decoration: none; font-size: 13px; font-weight: 500; }
        .page-btn.active { background: var(--primary); color: white; border-color: var(--primary); }
        details.panel > summary { list-style: none; cursor: pointer; transition: 0.2s; user-select: none; outline: none; }
        details.panel > summary::-webkit-details-marker { display: none; }
        details.panel > summary:hover { background: #f8fafc; }
        details.panel[open] > summary { border-bottom: 1px solid var(--border); background: #fdfdfd; color: var(--primary); }
        details.panel > summary::after { content: '+'; float: right; font-weight: bold; }
        details.panel[open] > summary::after { content: '-'; }
        .menu-toggle { display: none; background: none; border: none; font-size: 20px; color: var(--text-main); cursor: pointer; padding: 0 10px 0 0; }
        .sidebar-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; backdrop-filter: blur(2px); }
        .password-wrapper { position: relative; margin-bottom: 16px; }
        .password-wrapper input { padding-right: 40px; margin-bottom: 0; }
        .toggle-pwd { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #94a3b8; padding: 5px; z-index: 5; }
        .toggle-pwd:hover { color: var(--primary); }
        @media (max-width: 1024px) { .grid-4 { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) {
            aside { position: fixed; top: 0; left: 0; height: 100%; transform: translateX(-100%); width: 260px; box-shadow: 2px 0 10px rgba(0,0,0,0.2); }
            aside.open { transform: translateX(0); }
            .sidebar-overlay.show { display: block; }
            .menu-toggle { display: block; }
            .content { padding: 16px; }
            .grid-4 { grid-template-columns: 1fr; gap: 16px; }
            .panel-head { flex-direction: column; align-items: flex-start; gap: 12px; }
            .panel-head .btn, .panel-head input { width: 100%; margin: 0 !important; }
            .panel-head > div { width: 100%; }
            .page-select { width: 100%; margin-bottom: 10px; }
            .stat-value { font-size: 24px; }
            .table-responsive { border-radius: 0; }
            table { font-size: 12px; }
            td, th { padding: 12px 16px; }
        }
        .announcement-box { animation: slideDown 0.5s ease-out; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        /* 简单编辑弹窗样式 */
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2000; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-bg { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); backdrop-filter: blur(2px); }
        .modal-content { position: relative; background: #fff; width: 90%; max-width: 400px; padding: 24px; border-radius: 12px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1), 0 10px 10px -5px rgba(0,0,0,0.04); animation: modalPop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1); }
        @keyframes modalPop { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
        
        /* --- 仿友商面包屑与标签栏样式 --- */
        .breadcrumb-bar { padding: 12px 24px 0; font-size: 12px; color: #94a3b8; display: flex; align-items: center; gap: 6px; background: var(--body-bg); }
        .chrome-tabs { display: flex; align-items: center; gap: 8px; padding: 12px 24px 0; border-bottom: 1px solid #cbd5e1; background: var(--body-bg); margin-bottom: 0; flex-wrap: nowrap; overflow-x: auto; -webkit-overflow-scrolling: touch; }
        .chrome-tab { position: relative; display: flex; align-items: center; gap: 8px; padding: 6px 14px; background: #fff; border: 1px solid #e2e8f0; border-bottom: none; border-radius: 4px 4px 0 0; font-size: 12px; color: #64748b; cursor: pointer; transition: all 0.2s; text-decoration: none; white-space: nowrap; }
        .chrome-tab:hover { background: #f8fafc; color: #475569; }
        .chrome-tab.active { background: var(--primary); color: white; border-color: var(--primary); }
        .chrome-tab-close { font-size: 10px; opacity: 0.6; width: 14px; height: 14px; display: flex; align-items: center; justify-content: center; border-radius: 50%; transition: 0.2s; }
        .chrome-tab-close:hover { background: rgba(0,0,0,0.1); opacity: 1; }
        .chrome-tab.active .chrome-tab-close:hover { background: rgba(255,255,255,0.2); }
    </style>
</head>
<body>

<div class="sidebar-overlay" onclick="toggleSidebar()"></div>

<aside id="sidebar">
    <div class="brand"><img src="backend/logo.png" alt="Logo" class="brand-logo"> GuYi Aegis Pro <span style="font-size:10px; background:#3b82f6; padding:2px 6px; border-radius:4px; margin-left:8px;">Ent</span></div>
    <div class="nav">
        <div class="nav-label">概览</div>
        <a href="?tab=dashboard" class="<?=$tab=='dashboard'?'active':''?>"><i class="fas fa-chart-pie"></i> 首页</a>
        <div class="nav-label">多租户</div>
        <a href="?tab=apps" class="<?=$tab=='apps'?'active':''?>"><i class="fas fa-cubes"></i> 应用管理</a>
        <div class="nav-label">业务</div>
        <a href="?tab=list" class="<?=$tab=='list'?'active':''?>"><i class="fas fa-database"></i> 单码管理</a>
        <a href="?tab=create" class="<?=$tab=='create'?'active':''?>"><i class="fas fa-plus-circle"></i> 批量制卡</a>
        <div class="nav-label">监控</div>
        <a href="?tab=logs" class="<?=$tab=='logs'?'active':''?>"><i class="fas fa-history"></i> 审计日志</a>
        <a href="?tab=settings" class="<?=$tab=='settings'?'active':''?>"><i class="fas fa-cog"></i> 系统配置</a>
    </div>
    <div class="user-panel">
        <img src="backend/logo.png" alt="Admin" class="avatar-img">
        <div class="user-info"><div>Admin</div><span>Super User</span></div>
        <a href="?logout=1" class="logout"><i class="fas fa-sign-out-alt"></i></a>
    </div>
</aside>

<main>
    <header>
        <div style="display:flex; align-items:center;">
            <button class="menu-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
            <div class="title"><?=$currentTitle?></div>
        </div>
        <?php if($msg): ?><div style="font-size:13px; color:var(--success); background:#ecfdf5; padding:6px 12px; border-radius:20px; font-weight:600; display:none;"><i class="fas fa-check-circle"></i> <?=$msg?></div><?php endif; ?>
        <?php if($errorMsg): ?><div style="font-size:13px; color:var(--danger); background:#fef2f2; padding:6px 12px; border-radius:20px; font-weight:600; display:none;"><i class="fas fa-exclamation-circle"></i> <?=$errorMsg?></div><?php endif; ?>
    </header>

    <div class="breadcrumb-bar">
        首页 <span style="font-family:sans-serif;">&gt;</span> 单码应用 <span style="font-family:sans-serif;">&gt;</span> <?=$currentTitle?>
    </div>

    <div class="chrome-tabs" id="tabs-container">
        </div>

    <div class="content">
        <?php if($msg): ?><div style="margin-bottom:15px; font-size:13px; color:var(--success); background:#ecfdf5; padding:10px; border-radius:8px; border:1px solid #a7f3d0;"><i class="fas fa-check-circle"></i> <?=$msg?></div><?php endif; ?>
        <?php if($errorMsg): ?><div style="margin-bottom:15px; font-size:13px; color:var(--danger); background:#fef2f2; padding:10px; border-radius:8px; border:1px solid #fecaca;"><i class="fas fa-exclamation-circle"></i> <?=$errorMsg?></div><?php endif; ?>

        <?php if($tab == 'dashboard'): ?>
            <div class="panel announcement-box" style="background: linear-gradient(135deg, #eff6ff 0%, #ffffff 100%); border-left: 4px solid #3b82f6;">
                <div style="padding: 20px; display: flex; gap: 16px; align-items: flex-start;">
                    <div style="color: #3b82f6; font-size: 24px; padding-top: 2px;"><i class="fas fa-bullhorn"></i></div>
                    <div style="flex: 1;">
                        <div style="font-weight: 700; font-size: 16px; margin-bottom: 6px; color: #1e293b; display: flex; justify-content: space-between;">
                            <span>官方系统公告</span>
                            <span style="font-size: 11px; background: #3b82f6; color: white; padding: 2px 8px; border-radius: 10px; font-weight: 500;">NEW</span>
                        </div>
                        <div style="font-size: 14px; color: #475569; line-height: 1.6;">
                            欢迎使用 <b>GuYi Aegis Pro</b> 企业级验证管理系统。当前系统版本已更新至 V14.0。<br>
                            <ul style="margin: 5px 0 0 0; padding-left: 20px;">
                                <li>官方群：1077643184</li>
                                <li>有bug可以进去反馈 <a href="?tab=logs" style="color:#3b82f6;text-decoration:none;font-weight:600;">审计日志</a> 检查异常。</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid-4">
                <div class="stat-card"><div class="stat-label">总库存量 <div class="stat-icon" style="background:#eff6ff; color:#3b82f6;"><i class="fas fa-layer-group"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['total']); ?></div></div>
                <div class="stat-card"><div class="stat-label">活跃设备 <div class="stat-icon" style="background:#ecfdf5; color:#10b981;"><i class="fas fa-wifi"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['active']); ?></div></div>
                <div class="stat-card"><div class="stat-label">接入应用 <div class="stat-icon" style="background:#ede9fe; color:#8b5cf6;"><i class="fas fa-cubes"></i></div></div><div class="stat-value"><?php echo count($appList); ?></div></div>
                <div class="stat-card"><div class="stat-label">待售库存 <div class="stat-icon" style="background:#fffbeb; color:#d97706;"><i class="fas fa-tag"></i></div></div><div class="stat-value"><?php echo number_format($dashboardData['stats']['unused']); ?></div></div>
            </div>

            <div class="grid-4" style="grid-template-columns: 2fr 1fr;">
                 <div class="panel">
                    <div class="panel-head"><span class="panel-title">应用库存占比 (Top 5)</span></div>
                    <div class="table-responsive">
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
                                    <td><div style="display:flex;align-items:center;gap:8px;"><div style="flex:1;height:6px;background:#f1f5f9;border-radius:3px;overflow:hidden;min-width:50px;"><div style="width:<?=$percent?>%;height:100%;background:var(--primary);"></div></div><span style="font-size:12px;color:#64748b;width:36px;"><?=$percent?>%</span></div></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">类型分布</span></div>
                    <div style="height:200px;padding:20px;"><canvas id="typeChart"></canvas></div>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-head"><span class="panel-title">实时活跃设备监控</span><a href="?tab=list" class="btn btn-primary" style="font-size:12px; padding:6px 12px;">查看全部</a></div>
                <div class="table-responsive">
                    <table>
                        <thead><tr><th>所属应用</th><th>卡密</th><th>设备指纹</th><th>激活时间</th><th>到期时间</th></tr></thead>
                        <tbody>
                            <?php foreach(array_slice($activeDevices, 0, 5) as $dev): ?>
                            <tr>
                                <td><?php if($dev['app_id']>0): ?><span class="app-tag"><?=htmlspecialchars($dev['app_name'])?></span><?php else: ?><span style="color:#94a3b8;font-size:12px;">未分类</span><?php endif; ?></td>
                                <td><span class="code"><?php echo $dev['card_code']; ?></span></td>
                                <td style="font-family:'JetBrains Mono'; font-size:12px; color:#64748b;"><?php echo htmlspecialchars(substr($dev['device_hash'],0,12)).'...'; // [安全修复] XSS ?></td>
                                <td><?php echo date('H:i', strtotime($dev['activate_time'])); ?></td>
                                <td><span class="badge badge-success"><?php echo date('m-d H:i', strtotime($dev['expire_time'])); ?></span></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <?php if($tab == 'apps'): ?>
            <?php 
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http";
            $currentScriptDir = dirname($_SERVER['SCRIPT_NAME']);
            $currentScriptDir = rtrim($currentScriptDir, '/');
            $apiUrl = $protocol . "://" . $_SERVER['HTTP_HOST'] . $currentScriptDir . "/Verifyfile/api.php";
            ?>

            <div class="nav-segment">
                <button onclick="switchAppView('apps')" id="btn_apps" class="nav-pill active">应用列表</button>
                <button onclick="switchAppView('vars')" id="btn_vars" class="nav-pill">变量管理</button>
            </div>

            <div id="view_apps">
                <div class="panel">
                    <div class="panel-head">
                        <span class="panel-title">已接入应用列表</span>
                        <span style="font-size:12px;color:#94a3b8;">共 <?=count($appList)?> 个应用</span>
                    </div>
                    <div class="table-responsive">
                        <table>
                            <thead><tr><th>应用信息</th><th>App Key</th><th>数据统计</th><th>状态</th><th>操作</th></tr></thead>
                            <tbody>
                                <?php foreach($appList as $app): ?>
                                <tr>
                                    <td>
                                        <div style="font-weight:600; color:var(--text-main);"><?=htmlspecialchars($app['app_name'])?></div>
                                        <div style="font-size:11px;color:#94a3b8; margin-top:2px;">
                                            <?php if(!empty($app['app_version'])): ?>
                                                <span class="badge badge-neutral" style="padding:2px 6px; margin-right:4px; font-weight:500; font-size:10px;"><?=htmlspecialchars($app['app_version'])?></span>
                                            <?php endif; ?>
                                            <?=htmlspecialchars($app['notes'] ?: '暂无备注')?>
                                        </div>
                                    </td>
                                    <td>
                                        <div class="app-key-box" onclick="copy('<?=$app['app_key']?>')" style="cursor:pointer;" title="点击复制">
                                            <i class="fas fa-key" style="font-size:10px; color:#94a3b8;"></i>
                                            <span><?=$app['app_key']?></span>
                                        </div>
                                    </td>
                                    <td><span class="badge badge-primary"><?=number_format($app['card_count'])?> 张</span></td>
                                    <td><?=$app['status']==1 ? '<span class="badge badge-success">正常</span>' : '<span class="badge badge-danger">禁用</span>'?></td>
                                    <td>
                                        <button type="button" onclick="openEditApp(<?=$app['id']?>, '<?=addslashes($app['app_name'])?>', '<?=addslashes($app['app_version'])?>', '<?=addslashes($app['notes'])?>')" class="btn btn-primary btn-icon" title="编辑"><i class="fas fa-edit"></i></button>
                                        <button type="button" onclick="singleAction('toggle_app', <?=$app['id']?>)" class="btn <?=$app['status']==1?'btn-warning':'btn-secondary'?> btn-icon" title="<?=$app['status']==1?'禁用':'启用'?>"><i class="fas <?=$app['status']==1?'fa-ban':'fa-check'?>"></i></button>
                                        
                                        <?php if($app['card_count'] > 0): ?>
                                            <button type="button" onclick="alert('无法删除：该应用下仍有 <?=number_format($app['card_count'])?> 张卡密。\n\n请先进入「卡密库存」，筛选该应用并删除所有卡密后，方可删除应用。')" class="btn btn-secondary btn-icon" style="cursor:pointer; opacity: 0.6;" title="请先清空卡密"><i class="fas fa-trash"></i></button>
                                        <?php else: ?>
                                            <button type="button" onclick="singleAction('delete_app', <?=$app['id']?>)" class="btn btn-danger btn-icon" title="删除"><i class="fas fa-trash"></i></button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                                <?php if(count($appList) == 0): ?><tr><td colspan="5" style="text-align:center;padding:40px;color:#94a3b8;">暂无应用</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="grid-4" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
                    <details class="panel" open>
                        <summary class="panel-head"><span class="panel-title"><i class="fas fa-plus-circle" style="margin-right:8px;color:var(--primary);"></i>创建新应用</span></summary>
                        <div style="padding:24px;">
                            <form method="POST">
                                <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                                <input type="hidden" name="create_app" value="1">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">应用名称</label>
                                <input type="text" name="app_name" class="form-control" required placeholder="例如: Android 客户端">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">应用版本号</label>
                                <input type="text" name="app_version" class="form-control" placeholder="例如: v1.0">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">备注说明</label>
                                <textarea name="app_notes" class="form-control" style="height:80px;resize:none;" placeholder="可选：填写应用用途描述"></textarea>
                                <button type="submit" class="btn btn-primary" style="width:100%;">立即创建</button>
                            </form>
                        </div>
                    </details>

                    <details class="panel">
                        <summary class="panel-head"><span class="panel-title"><i class="fas fa-code" style="margin-right:8px;color:#8b5cf6;"></i>API 接口信息</span></summary>
                        <div style="padding:24px;">
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">接口地址</label>
                            <div class="app-key-box" style="margin-bottom:16px; display:flex; justify-content:space-between; width:100%;">
                                <span style="font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><?php echo $apiUrl; ?></span>
                                <i class="fas fa-copy" style="cursor:pointer;color:#3b82f6;" onclick="copy('<?php echo $apiUrl; ?>')"></i>
                            </div>
                            <div style="font-size:11px;color:#64748b;">支持通过 AppKey 获取公开变量。</div>
                        </div>
                    </details>
                </div>
                
                <div id="editAppModal" class="modal">
                    <div class="modal-bg" onclick="closeEditApp()"></div>
                    <div class="modal-content">
                        <div style="font-size:16px; font-weight:600; margin-bottom:16px;">编辑应用信息</div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="edit_app" value="1">
                            <input type="hidden" id="edit_app_id" name="app_id">
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">应用名称</label>
                            <input type="text" id="edit_app_name" name="app_name" class="form-control" required>
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">应用版本号</label>
                            <input type="text" id="edit_app_version" name="app_version" class="form-control">

                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">备注说明</label>
                            <textarea id="edit_app_notes" name="app_notes" class="form-control" style="height:80px;resize:none;" placeholder="输入内容..."></textarea>
                            
                            <div style="display:flex; gap:10px;">
                                <button type="button" class="btn btn-secondary" onclick="closeEditApp()" style="flex:1;">取消</button>
                                <button type="submit" class="btn btn-primary" style="flex:1;">保存修改</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div id="view_vars" style="display:none;">
                <div class="panel">
                    <div class="panel-head"><span class="panel-title">云端变量管理</span></div>
                    <div class="table-responsive">
                        <table>
                            <thead><tr><th>所属应用</th><th>键名 (Key)</th><th>值 (Value)</th><th>权限</th><th>操作</th></tr></thead>
                            <tbody>
                                <?php 
                                $hasVars = false;
                                foreach($appList as $app) {
                                    $vars = $db->getAppVariables($app['id']);
                                    foreach($vars as $v) {
                                        $hasVars = true;
                                        echo "<tr>";
                                        echo "<td><span class='app-tag'>".htmlspecialchars($app['app_name'])."</span></td>";
                                        echo "<td><span class='code' style='color:#db2777;'>".htmlspecialchars($v['key_name'])."</span></td>";
                                        echo "<td><div class='app-key-box' style='max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>".htmlspecialchars($v['value'])."</div></td>";
                                        echo "<td>".($v['is_public'] ? '<span class="badge badge-success">公开</span>' : '<span class="badge badge-warn">私有</span>')."</td>";
                                        echo "<td>
                                            <button type='button' onclick=\"openEditVar({$v['id']}, '".addslashes($v['key_name'])."', '".str_replace(array("\r\n", "\r", "\n"), '\n', addslashes($v['value']))."', {$v['is_public']})\" class='btn btn-primary btn-icon' title='编辑'><i class='fas fa-edit'></i></button>
                                            <button type='button' onclick=\"singleAction('del_var', {$v['id']}, 'var_id')\" class='btn btn-danger btn-icon' title='删除'><i class='fas fa-trash'></i></button>
                                        </td>";
                                        echo "</tr>";
                                    }
                                }
                                if(!$hasVars) echo "<tr><td colspan='5' style='text-align:center;padding:40px;color:#94a3b8;'>暂无数据</td></tr>";
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <details class="panel" open>
                    <summary class="panel-head"><span class="panel-title">添加变量</span></summary>
                    <div style="padding:24px;">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="add_var" value="1">
                            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:20px;">
                                <div>
                                    <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">所属应用</label>
                                    <select name="var_app_id" class="form-control" required>
                                        <option value="">-- 请选择 --</option>
                                        <?php foreach($appList as $app): ?>
                                            <option value="<?=$app['id']?>"><?=htmlspecialchars($app['app_name'])?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div>
                                    <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">键名 (Key)</label>
                                    <input type="text" name="var_key" class="form-control" placeholder="例如: update_url" required>
                                </div>
                            </div>
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">变量值</label>
                            <textarea name="var_value" class="form-control" style="height:80px;resize:none;" placeholder="输入内容..."></textarea>
                            <div style="margin-bottom:20px; display:flex; align-items:center;">
                                <input type="checkbox" id="var_public" name="var_public" value="1" style="width:16px;height:16px;margin-right:10px;">
                                <label for="var_public" style="font-size:13px; font-weight:600;">设为公开变量 (Public)</label>
                            </div>
                            <button type="submit" class="btn btn-success" style="width:100%;">保存变量</button>
                        </form>
                    </div>
                </details>

                <div id="editVarModal" class="modal">
                    <div class="modal-bg" onclick="closeEditVar()"></div>
                    <div class="modal-content">
                        <div style="font-size:16px; font-weight:600; margin-bottom:16px;">编辑变量</div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="edit_var" value="1">
                            <input type="hidden" id="edit_var_id" name="var_id">
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">键名 (Key)</label>
                            <input type="text" id="edit_var_key" name="var_key" class="form-control" required>
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">变量值</label>
                            <textarea id="edit_var_value" name="var_value" class="form-control" style="height:80px;resize:none;" placeholder="输入内容..."></textarea>
                            
                            <div style="margin-bottom:20px; display:flex; align-items:center;">
                                <input type="checkbox" id="edit_var_public" name="var_public" value="1" style="width:16px;height:16px;margin-right:10px;">
                                <label for="edit_var_public" style="font-size:13px; font-weight:600;">设为公开变量 (Public)</label>
                            </div>
                            
                            <div style="display:flex; gap:10px;">
                                <button type="button" class="btn btn-secondary" onclick="closeEditVar()" style="flex:1;">取消</button>
                                <button type="submit" class="btn btn-primary" style="flex:1;">保存修改</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            
            <script>
                function switchAppView(view) {
                    document.getElementById('btn_apps').classList.toggle('active', view === 'apps');
                    document.getElementById('btn_vars').classList.toggle('active', view === 'vars');
                    document.getElementById('view_apps').style.display = view === 'apps' ? 'block' : 'none';
                    document.getElementById('view_vars').style.display = view === 'vars' ? 'block' : 'none';
                }

                function openEditVar(id, key, val, pub) {
                    document.getElementById('edit_var_id').value = id;
                    document.getElementById('edit_var_key').value = key;
                    document.getElementById('edit_var_value').value = val;
                    document.getElementById('edit_var_public').checked = (pub == 1);
                    document.getElementById('editVarModal').classList.add('show');
                }
                function closeEditVar() { document.getElementById('editVarModal').classList.remove('show'); }

                // 修改：openEditApp 增加 version 参数处理
                function openEditApp(id, name, version, notes) {
                    document.getElementById('edit_app_id').value = id;
                    document.getElementById('edit_app_name').value = name;
                    document.getElementById('edit_app_version').value = version;
                    document.getElementById('edit_app_notes').value = notes;
                    document.getElementById('editAppModal').classList.add('show');
                }
                function closeEditApp() { document.getElementById('editAppModal').classList.remove('show'); }
            </script>
        <?php endif; ?>

        <?php if($tab == 'list'): ?>
            <div class="panel" style="margin-bottom: 24px;">
                <div class="panel-head"><span class="panel-title">请选择您要操作的应用</span></div>
                <div style="padding: 20px;">
                     <select class="form-control" style="margin: 0;" onchange="location.href='?tab=list&app_id='+this.value">
                        <option value="">-- 请先选择应用 --</option>
                        <?php foreach($appList as $app): ?>
                            <option value="<?=$app['id']?>" <?=($appFilter === $app['id']) ? 'selected' : ''?>><?=htmlspecialchars($app['app_name'])?></option>
                        <?php endforeach; ?>
                     </select>
                </div>
            </div>

            <?php if ($appFilter !== null || !empty($_GET['q'])): ?>
            
                <div class="nav-segment" style="margin-bottom: 20px;">
                    <a href="?tab=list&filter=all<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='all'?'active':''?>">全部</a>
                    <a href="?tab=list&filter=unused<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='unused'?'active':''?>">未激活</a>
                    <a href="?tab=list&filter=active<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='active'?'active':''?>">已激活</a>
                    <a href="?tab=list&filter=banned<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='banned'?'active':''?>">已封禁</a>
                </div>

                <div class="panel">
                    <form id="batchForm" method="POST">
                        <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                        <div class="panel-head">
                            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;width:100%;">
                                <input type="text" placeholder="搜索..." value="<?=$_GET['q']??''?>" class="form-control" style="margin:0;min-width:150px;flex:1;" onkeydown="if(event.key==='Enter'){event.preventDefault();window.location='?tab=list&q='+this.value;}">
                                <a href="?tab=list" class="btn btn-icon" style="background:#f1f5f9;color:#64748b;"><i class="fas fa-sync"></i></a>
                                <a href="?tab=create" class="btn btn-primary btn-icon"><i class="fas fa-plus"></i></a>
                            </div>
                            <div style="width:100%; display:flex; gap:5px; margin-top:10px; overflow-x:auto; padding-bottom:5px;">
                                <button type="submit" name="batch_export" value="1" class="btn" style="background:#6366f1;color:white;flex-shrink:0;">导出</button>
                                <button type="button" onclick="submitBatch('batch_unbind')" class="btn" style="background:#f59e0b;color:white;flex-shrink:0;">解绑</button>
                                <button type="button" onclick="batchAddTime()" class="btn" style="background:#10b981;color:white;flex-shrink:0;">加时</button>
                                <button type="button" onclick="submitBatch('batch_delete')" class="btn btn-danger" style="flex-shrink:0;">删除</button>
                            </div>
                        </div>
                        <input type="hidden" name="add_hours" id="addHoursInput">
                        <div class="table-responsive">
                            <table>
                                <thead><tr><th style="width:40px;text-align:center;"><input type="checkbox" onclick="toggleAll(this)"></th><th>应用</th><th>卡密代码</th><th>类型</th><th>状态</th><th>绑定设备</th><th>备注</th><th>操作</th></tr></thead>
                                <tbody>
                                    <?php foreach($cardList as $card): ?>
                                    <tr>
                                        <td style="text-align:center;"><input type="checkbox" name="ids[]" value="<?=$card['id']?>" class="row-check"></td>
                                        <td><?php if($card['app_id']>0 && !empty($card['app_name'])): ?><span class="app-tag"><?=htmlspecialchars($card['app_name'])?></span><?php else: ?><span style="color:#94a3b8;font-size:12px;">未分类</span><?php endif; ?></td>
                                        <td><span class="code" onclick="copy('<?=$card['card_code']?>')"><?=$card['card_code']?></span></td>
                                        <td><span style="font-weight:600;font-size:12px;"><?=CARD_TYPES[$card['card_type']]['name']??$card['card_type']?></span></td>
                                        <td>
                                            <?php 
                                            if($card['status']==2): echo '<span class="badge badge-danger">已封禁</span>';
                                            elseif($card['status']==1): echo (strtotime($card['expire_time'])>time()) ? (empty($card['device_hash'])?'<span class="badge badge-warn">待绑定</span>':'<span class="badge badge-success">使用中</span>') : '<span class="badge badge-danger">已过期</span>'; 
                                            else: echo '<span class="badge badge-neutral">闲置</span>'; endif; 
                                            ?>
                                        </td>
                                        <td>
                                            <?php if($card['status']==1 && !empty($card['device_hash'])): ?>
                                                <div style="font-family:'JetBrains Mono';font-size:11px;color:#64748b;" title="<?=$card['device_hash']?>">
                                                    <i class="fas fa-mobile-alt" style="margin-right:4px;"></i>
                                                    <?=substr($card['device_hash'], 0, 8).'...'?>
                                                </div>
                                            <?php else: ?>
                                                <span style="color:#cbd5e1;">-</span>
                                            <?php endif; ?>
                                        </td>
                                        <td style="color:#94a3b8;font-size:12px;max-width:100px;overflow:hidden;text-overflow:ellipsis;"><?=htmlspecialchars($card['notes']?:'-')?></td>
                                        <td style="display:flex;gap:5px;">
                                            <?php if($card['status']==1 && !empty($card['device_hash'])): ?><button type="button" onclick="singleAction('unbind_card', <?=$card['id']?>)" class="btn btn-warning btn-icon" title="解绑"><i class="fas fa-unlink"></i></button><?php endif; ?>
                                            <?php if($card['status']!=2): ?>
                                                <button type="button" onclick="singleAction('ban_card', <?=$card['id']?>)" class="btn btn-secondary btn-icon" style="color:#ef4444;"><i class="fas fa-ban"></i></button>
                                            <?php else: ?>
                                                <button type="button" onclick="singleAction('unban_card', <?=$card['id']?>)" class="btn btn-secondary btn-icon" style="color:#10b981;"><i class="fas fa-unlock"></i></button>
                                            <?php endif; ?>
                                            <button type="button" onclick="singleAction('del_card', <?=$card['id']?>)" class="btn btn-danger btn-icon"><i class="fas fa-trash"></i></button>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php if(empty($cardList)): ?><tr><td colspan="8" style="text-align:center;padding:30px;color:#94a3b8;">暂无数据</td></tr><?php endif; ?>
                                </tbody>
                            </table>
                        </div>

                        <div class="pagination">
                            <select class="page-select" onchange="window.location.href='?tab=list&filter=<?=$filterStr?>&page=1&limit='+this.value+'<?=isset($_GET['q'])?'&q='.htmlspecialchars($_GET['q']):''?><?=($appFilter!==null?'&app_id='.$appFilter:'')?>'">
                                <option value="10" <?=$perPage==10?'selected':''?>>10 条/页</option>
                                <option value="20" <?=$perPage==20?'selected':''?>>20 条/页</option>
                                <option value="50" <?=$perPage==50?'selected':''?>>50 条/页</option>
                                <option value="100" <?=$perPage==100?'selected':''?>>100 条/页</option>
                            </select>
                            <?php 
                            $queryParams = [
                                'tab' => 'list',
                                'limit' => $perPage,
                                'filter' => $filterStr
                            ];
                            if (!empty($_GET['q'])) {
                                $queryParams['q'] = $_GET['q'];
                            }
                            if ($appFilter !== null) {
                                $queryParams['app_id'] = $appFilter;
                            }
                            $getUrl = function($p) use ($queryParams) {
                                $queryParams['page'] = $p;
                                return '?' . http_build_query($queryParams);
                            };
                            if($page > 1) {
                                echo '<a href="'.$getUrl($page-1).'" class="page-btn"><i class="fas fa-chevron-left"></i></a>';
                            }
                            $start = max(1, $page - 2);
                            $end = min($totalPages, $page + 2);
                            if ($start > 1) {
                                echo '<a href="'.$getUrl(1).'" class="page-btn">1</a>';
                                if ($start > 2) echo '<span class="page-btn" style="border:none;background:transparent;cursor:default;">...</span>';
                            }
                            for ($i = $start; $i <= $end; $i++) {
                                if ($i == $page) {
                                    echo '<span class="page-btn active">'.$i.'</span>';
                                } else {
                                    echo '<a href="'.$getUrl($i).'" class="page-btn">'.$i.'</a>';
                                }
                            }
                            if ($end < $totalPages) {
                                if ($end < $totalPages - 1) echo '<span class="page-btn" style="border:none;background:transparent;cursor:default;">...</span>';
                                echo '<a href="'.$getUrl($totalPages).'" class="page-btn">'.$totalPages.'</a>';
                            }
                            if($page < $totalPages) {
                                echo '<a href="'.$getUrl($page+1).'" class="page-btn"><i class="fas fa-chevron-right"></i></a>';
                            }
                            ?>
                        </div>
                    </form>
                </div>
            
            <?php endif; ?>
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
                            <?php foreach($appList as $app): if($app['status']==0) continue; ?>
                                <option value="<?=$app['id']?>"><?=htmlspecialchars($app['app_name'])?></option>
                            <?php endforeach; ?>
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
                        <button type="submit" class="btn btn-primary" style="width:100%;">确认生成</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <?php if($tab == 'logs'): ?>
            <div class="panel">
                <div class="panel-head"><span class="panel-title">鉴权日志</span></div>
                <div class="table-responsive">
                    <table>
                        <thead><tr><th>时间</th><th>来源</th><th>卡密</th><th>IP/设备</th><th>结果</th></tr></thead>
                        <tbody>
                            <?php foreach($logs as $log): ?>
                            <tr>
                                <td style="color:#64748b;font-size:12px;"><?=date('m-d H:i',strtotime($log['access_time']))?></td>
                                <td><span class="app-tag" style="font-size:10px;"><?=htmlspecialchars($log['app_name']?:'-')?></td>
                                <td><span class="code" style="font-size:11px;"><?=substr($log['card_code'],0,10).'...'?></span></td>
                                <td style="font-size:11px;">
                                    <?=htmlspecialchars(substr($log['ip_address'],0,15)) // [安全修复] XSS?><br>
                                    <span style="color:#94a3b8;"><?=htmlspecialchars(substr($log['device_hash'],0,6)) // [安全修复] XSS?></span>
                                </td>
                                <td>
                                    <?php 
                                    $res=$log['result']; 
                                    // [安全修复] XSS - 转义$res
                                    echo (strpos($res,'成功')!==false||strpos($res,'活跃')!==false)?
                                        '<span class="badge badge-success" style="font-size:10px;">成功</span>' : 
                                        ((strpos($res,'失败')!==false)?
                                            '<span class="badge badge-danger" style="font-size:10px;">失败</span>' : 
                                            '<span class="badge badge-neutral" style="font-size:10px;">'.htmlspecialchars($res).'</span>'); 
                                    ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <?php if($tab == 'settings'): ?>
            <div class="panel" style="max-width:500px; margin:0 auto;">
                <div class="panel-head"><span class="panel-title">修改管理员密码</span></div>
                <div style="padding:24px;">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                        <input type="hidden" name="update_pwd" value="1">
                        
                        <div class="password-wrapper">
                            <input type="password" id="pwd1" name="new_pwd" class="form-control" placeholder="设置新密码" required>
                            <i class="fas fa-eye toggle-pwd" onclick="togglePwd()" title="显示/隐藏密码"></i>
                        </div>
                        
                        <div class="password-wrapper">
                            <input type="password" id="pwd2" name="confirm_pwd" class="form-control" placeholder="确认新密码" required>
                        </div>
                        
                        <button type="submit" class="btn btn-primary" style="width:100%;">更新密码</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>
    </div>
</main>

<div id="toast" class="toast"><i class="fas fa-check-circle" style="margin-right:8px; color:#4ade80;"></i> 已复制</div>

<script>
    function toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.querySelector('.sidebar-overlay');
        sidebar.classList.toggle('open');
        overlay.classList.toggle('show');
    }

    function togglePwd() {
        const p1 = document.getElementById('pwd1');
        const p2 = document.getElementById('pwd2');
        const icon = document.querySelector('.toggle-pwd');
        
        if (p1.type === 'password') {
            p1.type = 'text';
            p2.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            p1.type = 'password';
            p2.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }

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
        if(document.querySelectorAll('.row-check:checked').length === 0) { alert('请先勾选卡密'); return; }
        const hours = prompt("请输入增加小时数", "24");
        if(hours && !isNaN(hours)) { document.getElementById('addHoursInput').value = hours; submitBatch('batch_add_time'); }
    }
    function singleAction(actionName, id, idFieldName = 'id') {
        if(!confirm('确定操作？')) return;
        const form = document.createElement('form'); form.method = 'POST'; form.style.display = 'none';
        const actInput = document.createElement('input'); actInput.name = actionName; actInput.value = '1';
        const idInput = document.createElement('input'); 
        if(actionName === 'del_var') idInput.name = 'var_id'; else if (actionName.includes('app')) idInput.name = 'app_id'; else idInput.name = 'id';
        idInput.value = id;
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

    // --- [核心] 动态多标签页逻辑 ---
    (function(){
        // 当前页面信息
        const currentTabId = '<?=$tab?>';
        const currentTabTitle = '<?=$currentTitle?>';
        
        // 读取已存在的标签列表
        let openTabs = JSON.parse(localStorage.getItem('admin_tabs') || '[]');
        
        // 确保“首页”永远在第一个
        if (openTabs.length === 0 || openTabs[0].id !== 'dashboard') {
            // 如果列表空了或者第一个不是首页，重置/添加首页
            openTabs = openTabs.filter(t => t.id !== 'dashboard'); // 先移除旧的首页防止重复
            openTabs.unshift({id: 'dashboard', title: '首页'});
        }

        // 将当前页面添加到列表中（如果不在的话）
        const exists = openTabs.find(t => t.id === currentTabId);
        if (!exists) {
            openTabs.push({id: currentTabId, title: currentTabTitle});
        }

        // 保存回 LocalStorage
        localStorage.setItem('admin_tabs', JSON.stringify(openTabs));

        // 渲染标签 HTML
        const container = document.getElementById('tabs-container');
        let html = '';
        openTabs.forEach(t => {
            const isActive = (t.id === currentTabId) ? 'active' : '';
            const closeBtn = (t.id === 'dashboard') 
                ? '' 
                : `<i class="fas fa-times chrome-tab-close" onclick="closeTab(event, '${t.id}')"></i>`;
            
            html += `<a href="?tab=${t.id}" class="chrome-tab ${isActive}">
                        ${t.title} ${closeBtn}
                     </a>`;
        });
        container.innerHTML = html;

        // 全局关闭函数
        window.closeTab = function(e, tabId) {
            e.preventDefault(); 
            e.stopPropagation();
            
            // 从数组中移除
            openTabs = openTabs.filter(t => t.id !== tabId);
            localStorage.setItem('admin_tabs', JSON.stringify(openTabs));
            
            // 如果关闭的是当前激活的标签，跳转回首页
            if (tabId === currentTabId) {
                window.location.href = '?tab=dashboard';
            } else {
                // 如果关闭的是别的标签，只刷新 UI（这里简单起见刷新页面，或者用 JS 重新渲染）
                // 为了简单且不跳页，我们直接移除 DOM 元素并重新渲染上面的 HTML 逻辑即可。
                // 但因为是服务端渲染，点击其他标签会刷新。这里我们简单重绘 DOM 即可。
                e.target.closest('.chrome-tab').remove();
            }
        };
    })();
</script>
</body>
</html>
