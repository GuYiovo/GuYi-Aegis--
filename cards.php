<?php
// --- [防白屏核心] 强制开启错误提示 ---
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
    die('<div style="font-family:sans-serif;text-align:center;padding:50px;">
        <h2 style="color:#ef4444;">系统连接失败</h2>
        <p>无法连接到数据库，原因如下：</p>
        <code style="background:#f1f5f9;padding:10px;display:block;margin:20px auto;max-width:600px;border-radius:5px;">'.htmlspecialchars($e->getMessage()).'</code>
        <p>请检查 config.php 配置或数据库服务状态。</p>
    </div>');
}

// 安全检查
if (defined('SYS_SECRET') && strpos(SYS_SECRET, 'ENT_SECure_K3y') !== false) {
    die('<div style="color:red;font-weight:bold;padding:20px;text-align:center;">安全警告：请立即修改 config.php 中的 SYS_SECRET 常量！</div>');
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

// 检测设备类型 (用于背景图)
$is_mobile_client = preg_match("/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|mobi|palm|phone|pie|samsung|scp|wap|windows ce;iemobile|xhtml\\+xml)/i", $_SERVER["HTTP_USER_AGENT"]);
$bg_url = $is_mobile_client ? 'backend/pjt.png' : 'backend/pcpjt.png';

if (!isset($_SESSION['admin_logged_in'])): 

?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>登录 - GuYi Admin</title>
    <link rel="icon" href="backend/logo.png" type="image/png">
    <style>
        :root {
            --ay-accent-start: #ff7dc6;
            --ay-accent-end: #7aa8ff;
            --ay-text: #f3f6ff;
            --ay-sub: #b9c3e6;
            --ay-card: rgba(12, 14, 28, .55);
            --ay-stroke: rgba(255, 255, 255, .18);
            --ay-input: rgba(255, 255, 255, .06);
            --ay-input-h: 48px;
            --ay-radius: 20px;
        }

        html, body { height: 100%; }
        *, *::before, *::after { box-sizing: border-box; }

        body.ay-bg {
            margin: 0;
            color: var(--ay-text);
            font-family: ui-sans-serif, -apple-system, Segoe UI, Roboto, PingFang SC, Microsoft YaHei, system-ui, Arial;
            background-image: url('<?php echo $bg_url; ?>');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
            overflow-x: hidden;
        }

        .ay-dim {
            position: fixed; inset: 0; pointer-events: none;
            background: rgba(0,0,0,0.3);
            backdrop-filter: blur(5px);
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
            background: var(--ay-card); 
            backdrop-filter: blur(20px) saturate(140%);
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
    document.addEventListener('DOMContentLoaded', () => {
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

        const card = document.getElementById('ay-card');
        const wrap = document.querySelector('.ay-wrap');

        wrap.addEventListener('mousemove', (e) => {
            if (window.innerWidth <= 768) return; 

            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            card.style.setProperty('--mx', `${x}px`);
            card.style.setProperty('--my', `${y}px`);

            const rotateX = ((e.clientY - window.innerHeight / 2) / window.innerHeight) * -4;
            const rotateY = ((e.clientX - window.innerWidth / 2) / window.innerWidth) * 4;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });

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
// ----------------------------------------------------------------------
// 后端逻辑保持不变
// ----------------------------------------------------------------------

$tab = $_GET['tab'] ?? 'dashboard';
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

$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$perPage = isset($_GET['limit']) ? intval($_GET['limit']) : 20; 
if ($perPage < 5) $perPage = 20;
if ($perPage > 500) $perPage = 500;

$statusFilter = null;
$filterStr = $_GET['filter'] ?? 'all';
if ($filterStr === 'unused') $statusFilter = 0;
elseif ($filterStr === 'active') $statusFilter = 1;
elseif ($filterStr === 'banned') $statusFilter = 2;

$appFilter = isset($_GET['app_id']) && $_GET['app_id'] !== '' ? intval($_GET['app_id']) : null;
$isSearching = isset($_GET['q']) && !empty($_GET['q']);

$offset = ($page - 1) * $perPage;

try {
    if ($isSearching) {
        $allResults = $db->searchCards($_GET['q']);
        $totalCards = count($allResults);
        $cardList = array_slice($allResults, $offset, $perPage);
    } elseif ($appFilter !== null) {
        $totalCards = $db->getTotalCardCount($statusFilter, $appFilter);
        $cardList = $db->getCardsPaginated($perPage, $offset, $statusFilter, $appFilter);
    } else {
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
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <script src="assets/js/chart.js"></script>

    <style>
        :root {
            /* 极光磨砂侧边栏 - 深色高级感 */
            --sidebar-bg: rgba(22, 27, 46, 0.7);
            --sidebar-text: #a0aec0;
            --sidebar-active-bg: linear-gradient(90deg, rgba(99, 102, 241, 0.15), rgba(99, 102, 241, 0));
            --sidebar-active-text: #fff;
            --sidebar-border: 1px solid rgba(255, 255, 255, 0.08);

            /* 极光白卡片 - 剔透感 */
            --card-bg: rgba(255, 255, 255, 0.65);
            --card-border: 1px solid rgba(255, 255, 255, 0.4);
            --card-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
            --card-radius: 24px;
            
            --text-main: #2d3748;
            --text-muted: #718096;
            
            /* 新主色调 - 靛蓝与紫 */
            --primary: #6366f1; /* Indigo 500 */
            --primary-glow: rgba(99, 102, 241, 0.3);
            
            --success: #10b981;
            --danger: #f43f5e;
            --warning: #f59e0b;

            /* 小组件圆角 */
            --input-radius: 12px;
            --btn-radius: 12px;
        }

        * { box-sizing: border-box; outline: none; -webkit-tap-highlight-color: transparent; }
        
        body { 
            margin: 0; 
            font-family: 'Outfit', sans-serif; 
            background-color: transparent;
            color: var(--text-main); 
            display: flex; 
            height: 100vh; 
            overflow: hidden; 
            background-image: url('<?php echo $bg_url; ?>');
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }

        /* 侧边栏重构 */
        aside { 
            width: 270px; 
            background: var(--sidebar-bg); 
            backdrop-filter: blur(40px) saturate(180%);
            -webkit-backdrop-filter: blur(40px) saturate(180%);
            flex-shrink: 0; 
            display: flex; 
            flex-direction: column; 
            border-right: var(--sidebar-border); 
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
            z-index: 1000; 
            box-shadow: 4px 0 24px rgba(0,0,0,0.1);
        }

        .brand { 
            height: 80px; 
            display: flex; align-items: center; 
            padding: 0 28px; 
            color: white; 
            font-weight: 700; font-size: 18px; 
            letter-spacing: -0.5px;
            background: linear-gradient(to bottom, rgba(255,255,255,0.05), transparent);
            border-bottom: var(--sidebar-border);
        }
        .brand-logo { 
            width: 36px; height: 36px; 
            border-radius: 10px; margin-right: 14px; 
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
            border: 1px solid rgba(255,255,255,0.2); 
        }
        
        .nav { flex: 1; padding: 24px 16px; overflow-y: auto; }
        .nav-label { 
            font-size: 11px; text-transform: uppercase; 
            color: rgba(255,255,255,0.3); font-weight: 700; 
            margin: 20px 0 10px 14px; letter-spacing: 1px; 
        }
        .nav a { 
            display: flex; align-items: center; padding: 13px 18px; 
            color: var(--sidebar-text); text-decoration: none; 
            border-radius: var(--btn-radius); margin-bottom: 6px; 
            font-size: 14px; font-weight: 500; 
            transition: all 0.25s ease; 
            position: relative;
            overflow: hidden;
        }
        .nav a:hover { 
            background: rgba(255, 255, 255, 0.05); 
            color: white; 
            transform: translateX(4px);
        }
        .nav a.active { 
            background: var(--sidebar-active-bg); 
            color: var(--sidebar-active-text); 
            font-weight: 600;
        }
        .nav a.active::before {
            content: ''; position: absolute; left: 0; top: 15%; height: 70%; width: 3px; 
            background: #818cf8; border-radius: 0 4px 4px 0;
            box-shadow: 0 0 12px #818cf8;
        }
        .nav a i { width: 24px; margin-right: 12px; font-size: 16px; opacity: 0.8; text-align: center; }
        .nav a.active i { color: #818cf8; opacity: 1; }

        .user-panel { 
            margin: 20px; padding: 16px; 
            background: rgba(255, 255, 255, 0.05); 
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px; 
            display: flex; align-items: center; gap: 12px; 
            backdrop-filter: blur(10px);
        }
        .avatar-img { width: 38px; height: 38px; border-radius: 10px; border: 2px solid rgba(255,255,255,0.1); object-fit: cover; }
        .user-info div { font-size: 14px; color: white; font-weight: 600; }
        .user-info span { font-size: 11px; color: rgba(255,255,255,0.4); }
        .logout { margin-left: auto; color: rgba(255,255,255,0.5); cursor: pointer; transition: 0.2s; padding: 8px; border-radius: 8px; }
        .logout:hover { color: #f43f5e; background: rgba(244, 63, 94, 0.1); }
        
        main { flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        
        header { 
            height: 80px; 
            padding: 0 32px; 
            display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; z-index: 10; 
            /* 悬浮顶栏设计 */
            margin: 0;
            background: transparent;
        }
        .title { 
            font-size: 22px; font-weight: 700; color: #1e293b; 
            text-shadow: 0 2px 10px rgba(255,255,255,0.5);
        }
        
        .content { flex: 1; overflow-y: auto; padding: 0 32px 32px; -webkit-overflow-scrolling: touch; }
        
        /* 玻璃拟态卡片升级 */
        .panel, .stat-card { 
            background: var(--card-bg); 
            backdrop-filter: blur(25px) saturate(120%);
            -webkit-backdrop-filter: blur(25px) saturate(120%);
            border: var(--card-border); 
            border-radius: var(--card-radius); 
            box-shadow: var(--card-shadow);
            transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            overflow: hidden; /* 修复内部圆角溢出 */
        }
        .panel:hover, .stat-card:hover { 
            background: rgba(255, 255, 255, 0.75);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.08);
            border-color: rgba(255,255,255,0.6);
        }
        
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 32px; }
        
        /* 统计卡片独特设计 */
        .stat-card { padding: 24px; position: relative; display: flex; flex-direction: column; justify-content: center; }
        .stat-label { color: var(--text-muted); font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .stat-value { font-size: 36px; font-weight: 700; color: #1e293b; letter-spacing: -1.5px; line-height: 1; }
        .stat-icon { 
            position: absolute; right: 20px; top: 50%; transform: translateY(-50%);
            width: 56px; height: 56px; border-radius: 16px; 
            display: flex; align-items: center; justify-content: center; font-size: 24px; 
            opacity: 0.9;
        }
        
        /* 统计卡片独立配色 */
        .stat-card:nth-child(1) .stat-icon { background: linear-gradient(135deg, #dbeafe, #bfdbfe); color: #2563eb; }
        .stat-card:nth-child(2) .stat-icon { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #059669; }
        .stat-card:nth-child(3) .stat-icon { background: linear-gradient(135deg, #ede9fe, #ddd6fe); color: #7c3aed; }
        .stat-card:nth-child(4) .stat-icon { background: linear-gradient(135deg, #ffedd5, #fed7aa); color: #ea580c; }

        .panel { margin-bottom: 28px; }
        .panel-head { 
            padding: 20px 28px; 
            border-bottom: 1px solid rgba(0,0,0,0.03); 
            display: flex; justify-content: space-between; align-items: center; 
            background: rgba(255, 255, 255, 0.3); 
            flex-wrap: wrap; gap: 10px; 
        }
        .panel-title { font-size: 16px; font-weight: 700; color: #1e293b; display: flex; align-items: center; gap: 8px; }
        
        /* 表格完全重构 - 无框悬浮感 */
        .table-responsive { width: 100%; overflow-x: auto; border-radius: 0 0 var(--card-radius) var(--card-radius); }
        table { width: 100%; border-collapse: collapse; font-size: 13px; white-space: nowrap; }
        th { 
            text-align: left; padding: 18px 28px; 
            background: rgba(248, 250, 252, 0.5); 
            color: #64748b; font-weight: 600; 
            text-transform: uppercase; font-size: 11px; letter-spacing: 0.8px; 
            border-bottom: 1px solid rgba(0,0,0,0.03);
        }
        /* 修复表头圆角 */
        th:first-child { border-top-left-radius: 0; }
        th:last-child { border-top-right-radius: 0; }
        
        td { padding: 18px 28px; border-bottom: 1px solid rgba(0,0,0,0.02); color: var(--text-main); vertical-align: middle; transition: all 0.2s; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255, 255, 255, 0.6); }
        
        /* 徽章优化 */
        .badge { display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; line-height: 1.4; letter-spacing: 0.3px; }
        .badge-success { background: rgba(16, 185, 129, 0.12); color: #047857; }
        .badge-warn { background: rgba(245, 158, 11, 0.12); color: #b45309; }
        .badge-danger { background: rgba(244, 63, 94, 0.12); color: #be123c; }
        .badge-neutral { background: rgba(148, 163, 184, 0.15); color: #475569; }
        .badge-primary { background: rgba(99, 102, 241, 0.12); color: #4338ca; }
        
        .code { 
            font-family: 'JetBrains Mono', monospace; 
            background: rgba(255,255,255,0.6); 
            padding: 6px 12px; border-radius: 8px; 
            font-size: 12px; color: #334155; 
            border: 1px solid rgba(0,0,0,0.04); 
            cursor: pointer; transition: all 0.2s; 
            font-weight: 500;
        }
        .code:hover { background: #fff; border-color: #818cf8; color: #4f46e5; box-shadow: 0 2px 8px rgba(99, 102, 241, 0.15); }
        
        /* 按钮升级 - 渐变与阴影 - 圆角修复 */
        .btn { 
            display: inline-flex; align-items: center; padding: 9px 18px; 
            border-radius: var(--btn-radius); font-size: 13px; font-weight: 600; 
            cursor: pointer; transition: all 0.2s ease; 
            border: 1px solid transparent; text-decoration: none; justify-content: center; 
        }
        .btn:hover { transform: translateY(-2px); filter: brightness(1.05); }
        .btn:active { transform: translateY(0); }
        
        .btn-primary { 
            background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); 
            color: white; 
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
        }
        .btn-danger { background: #fff1f2; color: #be123c; border-color: #fecdd3; }
        .btn-danger:hover { background: #ffe4e6; box-shadow: 0 4px 12px rgba(244, 63, 94, 0.15); }
        .btn-warning { background: #fff7ed; color: #c2410c; border-color: #fed7aa; }
        .btn-secondary { background: #f8fafc; color: #475569; border-color: #e2e8f0; }
        .btn-icon { padding: 9px; min-width: 36px; height: 36px; }

        /* 输入框圆角修复与交互增强 */
        .form-control { 
            width: 100%; padding: 12px 16px; 
            border: 1px solid rgba(203, 213, 225, 0.8); 
            border-radius: var(--input-radius); margin-bottom: 16px; font-size: 14px; 
            -webkit-appearance: none; background: rgba(255,255,255,0.7); 
            transition: all 0.2s; 
        }
        .form-control:focus { background: #fff; border-color: #6366f1; box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.1); }
        
        .toast { position: fixed; bottom: 30px; right: 30px; background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(12px); color: #1e293b; padding: 14px 24px; border-radius: 16px; opacity: 0; transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1); transform: translateY(20px); z-index: 2000; font-size: 14px; font-weight: 500; box-shadow: 0 10px 30px -5px rgba(0,0,0,0.1); border: 1px solid rgba(0,0,0,0.05); display: flex; align-items: center; }
        .toast.show { opacity: 1; transform: translateY(0); }
        .toast i { color: #10b981; font-size: 18px; margin-right: 10px; }
        
        .nav-segment { 
            background: rgba(255, 255, 255, 0.25); 
            backdrop-filter: blur(12px);
            padding: 5px; border-radius: 14px; display: inline-flex; 
            border: 1px solid rgba(255,255,255,0.4); 
            margin-bottom: 24px; width: 100%; overflow-x: auto; 
        }
        .nav-pill { 
            padding: 10px 24px; border-radius: 10px; 
            font-size: 13px; font-weight: 600; color: var(--text-muted); 
            background: transparent; border: none; cursor: pointer; 
            transition: all 0.2s; white-space: nowrap; text-decoration: none; 
            display: inline-block; text-align: center; flex: 1;
        }
        .nav-pill:hover { color: #1e293b; background: rgba(255,255,255,0.3); }
        .nav-pill.active { 
            background: #fff; color: #4f46e5; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.05); 
        }
        
        /* 标签页优化 */
        .chrome-tabs { 
            display: flex; align-items: center; gap: 8px; padding: 12px 32px 0; 
            margin-bottom: 0; flex-wrap: nowrap; overflow-x: auto; 
            mask-image: linear-gradient(to right, black 95%, transparent 100%);
        }
        .chrome-tab { 
            position: relative; display: flex; align-items: center; gap: 10px; padding: 10px 20px; 
            background: rgba(255,255,255,0.35); 
            border: 1px solid rgba(255, 255, 255, 0.3); 
            border-radius: 12px; 
            font-size: 13px; color: #64748b; font-weight: 600;
            cursor: pointer; transition: all 0.2s; text-decoration: none; white-space: nowrap; 
        }
        .chrome-tab:hover { background: rgba(255, 255, 255, 0.6); transform: translateY(-1px); }
        .chrome-tab.active { 
            background: rgba(255, 255, 255, 0.85); color: #4f46e5; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            border-color: rgba(255,255,255,0.8);
        }
        
        details.panel > summary { list-style: none; cursor: pointer; transition: 0.2s; user-select: none; outline: none; }
        details.panel > summary::-webkit-details-marker { display: none; }
        details.panel > summary:hover { background: rgba(255, 255, 255, 0.4); }
        
        .menu-toggle { display: none; background: none; border: none; font-size: 20px; color: #1e293b; cursor: pointer; padding: 0 10px 0 0; }
        .sidebar-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(15, 23, 42, 0.4); z-index: 999; backdrop-filter: blur(4px); }
        
        .breadcrumb-bar { 
            padding: 8px 32px 4px; font-size: 12px; color: #64748b; 
            display: flex; align-items: center; gap: 8px; font-weight: 500; 
        }
        .announcement-box { 
            background: linear-gradient(135deg, rgba(238, 242, 255, 0.8) 0%, rgba(255, 255, 255, 0.8) 100%); 
            border: 1px solid rgba(255,255,255,0.6);
            backdrop-filter: blur(10px);
            border-radius: var(--card-radius);
            animation: slideDown 0.5s cubic-bezier(0.2, 0.8, 0.2, 1); 
            box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.15);
        }
        /* 修复公告闪烁：覆盖 panel:hover 的背景 */
        .panel.announcement-box:hover {
            background: linear-gradient(135deg, rgba(238, 242, 255, 0.9) 0%, rgba(255, 255, 255, 0.95) 100%);
            border-color: rgba(255,255,255,0.9);
        }

        .modal-bg { backdrop-filter: blur(8px); background: rgba(15, 23, 42, 0.2); }
        .modal-content { 
            background: rgba(255, 255, 255, 0.85); 
            backdrop-filter: blur(25px); 
            border: 1px solid rgba(255,255,255,0.8);
            border-radius: 24px; 
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); 
        }

        @media (max-width: 1024px) { .grid-4 { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) {
            aside { position: fixed; top: 0; left: 0; height: 100%; transform: translateX(-100%); box-shadow: 10px 0 30px rgba(0,0,0,0.2); }
            aside.open { transform: translateX(0); }
            .sidebar-overlay.show { display: block; }
            .menu-toggle { display: block; }
            header { padding: 0 20px; }
            .content { padding: 0 16px 32px; }
            .grid-4 { grid-template-columns: 1fr; gap: 16px; }
            .panel-head { flex-direction: column; align-items: flex-start; gap: 12px; }
            .panel-head .btn, .panel-head input { width: 100%; margin: 0 !important; }
            .panel-head > div { width: 100%; }
            .stat-value { font-size: 28px; }
            .stat-icon { width: 48px; height: 48px; font-size: 20px; }
            td, th { padding: 14px 20px; }
            .chrome-tabs { padding: 12px 16px 0; }
            .breadcrumb-bar { padding: 8px 20px 4px; }
        }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-15px); } to { opacity: 1; transform: translateY(0); } }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2000; justify-content: center; align-items: center; }
        .modal.show { display: flex; }
        .modal-bg { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }
        .modal-content { position: relative; width: 90%; max-width: 420px; padding: 28px; animation: modalPop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1); }
        @keyframes modalPop { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
        .password-wrapper { position: relative; margin-bottom: 16px; }
        .password-wrapper input { padding-right: 40px; margin-bottom: 0; }
        .toggle-pwd { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #94a3b8; padding: 5px; z-index: 5; }
        .toggle-pwd:hover { color: var(--primary); }
    </style>
</head>
<body>

<div class="sidebar-overlay" onclick="toggleSidebar()"></div>

<aside id="sidebar">
    <div class="brand">
        <img src="backend/logo.png" alt="Logo" class="brand-logo"> 
        <div style="display:flex; flex-direction:column; justify-content:center;">
            <span style="line-height:1;">GuYi Aegis</span>
            <span style="font-size:11px; color:rgba(255,255,255,0.4); font-weight:500; margin-top:4px;">Pro Enterprise</span>
        </div>
    </div>
    <div class="nav">
        <div class="nav-label">概览</div>
        <a href="?tab=dashboard" class="<?=$tab=='dashboard'?'active':''?>"><i class="fas fa-chart-pie"></i> 仪表盘</a>
        <div class="nav-label">核心业务</div>
        <a href="?tab=apps" class="<?=$tab=='apps'?'active':''?>"><i class="fas fa-cubes"></i> 应用列表</a>
        <a href="?tab=list" class="<?=$tab=='list'?'active':''?>"><i class="fas fa-database"></i> 卡密库存</a>
        <a href="?tab=create" class="<?=$tab=='create'?'active':''?>"><i class="fas fa-plus-circle"></i> 批量制卡</a>
        <div class="nav-label">系统监控</div>
        <a href="?tab=logs" class="<?=$tab=='logs'?'active':''?>"><i class="fas fa-history"></i> 审计日志</a>
        <a href="?tab=settings" class="<?=$tab=='settings'?'active':''?>"><i class="fas fa-cog"></i> 全局配置</a>
    </div>
    <div class="user-panel">
        <img src="backend/logo.png" alt="Admin" class="avatar-img">
        <div class="user-info"><div>Admin</div><span>超级管理员</span></div>
        <a href="?logout=1" class="logout" title="退出登录"><i class="fas fa-sign-out-alt"></i></a>
    </div>
</aside>

<main>
    <header>
        <div style="display:flex; align-items:center;">
            <button class="menu-toggle" onclick="toggleSidebar()"><i class="fas fa-bars"></i></button>
            <div class="title"><?=$currentTitle?></div>
        </div>
        <?php if($msg): ?><div style="font-size:13px; color:#059669; background:rgba(16, 185, 129, 0.15); padding:8px 16px; border-radius:12px; font-weight:600; display:flex; align-items:center; gap:6px;"><i class="fas fa-check-circle"></i> <?=$msg?></div><?php endif; ?>
        <?php if($errorMsg): ?><div style="font-size:13px; color:#dc2626; background:rgba(239, 68, 68, 0.15); padding:8px 16px; border-radius:12px; font-weight:600; display:flex; align-items:center; gap:6px;"><i class="fas fa-exclamation-circle"></i> <?=$errorMsg?></div><?php endif; ?>
    </header>

    <div class="breadcrumb-bar">
        GuYi System <i class="fas fa-chevron-right" style="font-size:8px; opacity:0.5;"></i> <?=$currentTitle?>
    </div>

    <div class="chrome-tabs" id="tabs-container">
        <!-- JS Generated Tabs -->
    </div>

    <div class="content">
        <?php if($tab == 'dashboard'): ?>
            <div class="panel announcement-box" style="margin-top: 20px;">
                <div style="padding: 24px; display: flex; gap: 20px; align-items: flex-start;">
                    <div style="width: 48px; height: 48px; border-radius: 12px; background: rgba(59, 130, 246, 0.1); display:flex; align-items:center; justify-content:center; color:#3b82f6; font-size: 20px;"><i class="fas fa-bullhorn"></i></div>
                    <div style="flex: 1;">
                        <div style="font-weight: 700; font-size: 17px; margin-bottom: 8px; color: #1e293b; display: flex; justify-content: space-between; align-items:center;">
                            <span>欢迎回来，指挥官</span>
                            <span style="font-size: 11px; background: #6366f1; color: white; padding: 4px 10px; border-radius: 20px; font-weight: 600; letter-spacing:0.5px;">V15.0 PRO</span>
                        </div>
                        <div style="font-size: 14px; color: #475569; line-height: 1.6;">
                            系统当前运行状态良好，所有节点连接正常。<br>
                            <div style="margin-top:8px; font-size:12px; opacity:0.8;"><i class="fas fa-info-circle"></i> 如需帮助，请访问官方群：1077643184 或查看审计日志排查异常。</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid-4">
                <div class="stat-card">
                    <div class="stat-label">总库存量</div>
                    <div class="stat-value"><?php echo number_format($dashboardData['stats']['total']); ?></div>
                    <div class="stat-icon"><i class="fas fa-layer-group"></i></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">活跃设备</div>
                    <div class="stat-value"><?php echo number_format($dashboardData['stats']['active']); ?></div>
                    <div class="stat-icon"><i class="fas fa-wifi"></i></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">接入应用</div>
                    <div class="stat-value"><?php echo count($appList); ?></div>
                    <div class="stat-icon"><i class="fas fa-cubes"></i></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">待售库存</div>
                    <div class="stat-value"><?php echo number_format($dashboardData['stats']['unused']); ?></div>
                    <div class="stat-icon"><i class="fas fa-tag"></i></div>
                </div>
            </div>

            <div class="grid-4" style="grid-template-columns: 2fr 1fr;">
                 <div class="panel">
                    <div class="panel-head"><span class="panel-title"><i class="fas fa-chart-bar" style="color:#6366f1;"></i> 应用库存占比</span></div>
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
                                    <td><div style="display:flex;align-items:center;gap:12px;"><div style="flex:1;height:8px;background:rgba(0,0,0,0.05);border-radius:4px;overflow:hidden;min-width:60px;"><div style="width:<?=$percent?>%;height:100%;background:linear-gradient(90deg, #6366f1, #818cf8); border-radius:4px;"></div></div><span style="font-size:12px;color:#64748b;font-weight:600;width:36px;"><?=$percent?>%</span></div></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-head"><span class="panel-title"><i class="fas fa-chart-pie" style="color:#10b981;"></i> 类型分布</span></div>
                    <div style="height:200px;padding:20px;"><canvas id="typeChart"></canvas></div>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-head"><span class="panel-title"><i class="fas fa-satellite-dish" style="color:#f59e0b;"></i> 实时活跃设备</span><a href="?tab=list" class="btn btn-primary" style="font-size:12px; padding:6px 14px;">全部列表</a></div>
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

            <div class="nav-segment" style="margin-top:20px;">
                <button onclick="switchAppView('apps')" id="btn_apps" class="nav-pill active"><i class="fas fa-list-ul" style="margin-right:6px;"></i>应用列表</button>
                <button onclick="switchAppView('vars')" id="btn_vars" class="nav-pill"><i class="fas fa-sliders-h" style="margin-right:6px;"></i>变量管理</button>
            </div>

            <div id="view_apps">
                <div class="panel">
                    <div class="panel-head">
                        <span class="panel-title">已接入应用列表</span>
                        <span style="font-size:12px;color:#94a3b8; font-weight:500;">共 <?=count($appList)?> 个应用</span>
                    </div>
                    <div class="table-responsive">
                        <table>
                            <thead><tr><th>应用信息</th><th>App Key</th><th>数据统计</th><th>状态</th><th>操作</th></tr></thead>
                            <tbody>
                                <?php foreach($appList as $app): ?>
                                <tr>
                                    <td>
                                        <div style="font-weight:600; color:var(--text-main); font-size:14px;"><?=htmlspecialchars($app['app_name'])?></div>
                                        <div style="font-size:11px;color:#94a3b8; margin-top:4px; display:flex; align-items:center;">
                                            <?php if(!empty($app['app_version'])): ?>
                                                <span class="badge badge-neutral" style="padding:2px 6px; margin-right:6px; font-weight:600; font-size:10px;"><?=htmlspecialchars($app['app_version'])?></span>
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
                                <?php if(count($appList) == 0): ?><tr><td colspan="5" style="text-align:center;padding:40px;color:#94a3b8;">暂无应用，请点击下方创建</td></tr><?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="grid-4" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
                    <details class="panel" open>
                        <summary class="panel-head"><span class="panel-title"><i class="fas fa-plus-circle" style="margin-right:8px;color:var(--primary);"></i>创建新应用</span></summary>
                        <div style="padding:28px;">
                            <form method="POST">
                                <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                                <input type="hidden" name="create_app" value="1">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;color:#475569;">应用名称</label>
                                <input type="text" name="app_name" class="form-control" required placeholder="例如: Android 客户端">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;color:#475569;">应用版本号</label>
                                <input type="text" name="app_version" class="form-control" placeholder="例如: v1.0">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;color:#475569;">备注说明</label>
                                <textarea name="app_notes" class="form-control" style="height:80px;resize:none;" placeholder="可选：填写应用用途描述"></textarea>
                                <button type="submit" class="btn btn-primary" style="width:100%; padding:12px;">立即创建</button>
                            </form>
                        </div>
                    </details>

                    <details class="panel">
                        <summary class="panel-head"><span class="panel-title"><i class="fas fa-code" style="margin-right:8px;color:#8b5cf6;"></i>API 接口信息</span></summary>
                        <div style="padding:28px;">
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;color:#475569;">接口地址</label>
                            <div class="app-key-box" style="margin-bottom:16px; display:flex; justify-content:space-between; width:100%; padding:12px;">
                                <span style="font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><?php echo $apiUrl; ?></span>
                                <i class="fas fa-copy" style="cursor:pointer;color:#6366f1;" onclick="copy('<?php echo $apiUrl; ?>')"></i>
                            </div>
                            <div style="font-size:12px;color:#64748b; line-height:1.5;">通过 AppKey 验证卡密或获取公开变量。请妥善保管您的 AppKey。</div>
                        </div>
                    </details>
                </div>
                
                <div id="editAppModal" class="modal">
                    <div class="modal-bg" onclick="closeEditApp()"></div>
                    <div class="modal-content">
                        <div style="font-size:18px; font-weight:700; margin-bottom:20px; color:#1e293b;">编辑应用信息</div>
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
                            
                            <div style="display:flex; gap:12px; margin-top:8px;">
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
                                        echo "<td><span class='code' style='color:#ec4899;background:rgba(236, 72, 153, 0.1);border-color:rgba(236, 72, 153, 0.2);'>".htmlspecialchars($v['key_name'])."</span></td>";
                                        echo "<td><div class='app-key-box' style='max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>".htmlspecialchars($v['value'])."</div></td>";
                                        echo "<td>".($v['is_public'] ? '<span class="badge badge-success">公开</span>' : '<span class="badge badge-warn">私有</span>')."</td>";
                                        echo "<td>
                                            <button type='button' onclick=\"openEditVar({$v['id']}, '".addslashes($v['key_name'])."', '".str_replace(array("\r\n", "\r", "\n"), '\n', addslashes($v['value']))."', {$v['is_public']})\" class='btn btn-primary btn-icon' title='编辑'><i class='fas fa-edit'></i></button>
                                            <button type='button' onclick=\"singleAction('del_var', {$v['id']}, 'var_id')\" class='btn btn-danger btn-icon' title='删除'><i class='fas fa-trash'></i></button>
                                        </td>";
                                        echo "</tr>";
                                    }
                                }
                                if(!$hasVars) echo "<tr><td colspan='5' style='text-align:center;padding:40px;color:#94a3b8;'>暂无变量数据</td></tr>";
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <details class="panel" open>
                    <summary class="panel-head"><span class="panel-title">添加变量</span></summary>
                    <div style="padding:28px;">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="add_var" value="1">
                            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:24px;">
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
                            <div style="margin-bottom:24px; display:flex; align-items:center;">
                                <input type="checkbox" id="var_public" name="var_public" value="1" style="width:18px;height:18px;margin-right:10px;accent-color:var(--primary);">
                                <label for="var_public" style="font-size:13px; font-weight:600;">设为公开变量 (Public)</label>
                            </div>
                            <button type="submit" class="btn btn-success" style="width:100%; padding:12px;">保存变量</button>
                        </form>
                    </div>
                </details>

                <div id="editVarModal" class="modal">
                    <div class="modal-bg" onclick="closeEditVar()"></div>
                    <div class="modal-content">
                        <div style="font-size:18px; font-weight:700; margin-bottom:20px;">编辑变量</div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                            <input type="hidden" name="edit_var" value="1">
                            <input type="hidden" id="edit_var_id" name="var_id">
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">键名 (Key)</label>
                            <input type="text" id="edit_var_key" name="var_key" class="form-control" required>
                            
                            <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">变量值</label>
                            <textarea id="edit_var_value" name="var_value" class="form-control" style="height:80px;resize:none;" placeholder="输入内容..."></textarea>
                            
                            <div style="margin-bottom:24px; display:flex; align-items:center;">
                                <input type="checkbox" id="edit_var_public" name="var_public" value="1" style="width:18px;height:18px;margin-right:10px;accent-color:var(--primary);">
                                <label for="edit_var_public" style="font-size:13px; font-weight:600;">设为公开变量 (Public)</label>
                            </div>
                            
                            <div style="display:flex; gap:12px;">
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
            <div class="panel" style="margin-bottom: 24px; margin-top:20px;">
                <div class="panel-head"><span class="panel-title">应用选择</span></div>
                <div style="padding: 24px;">
                     <select class="form-control" style="margin: 0;" onchange="location.href='?tab=list&app_id='+this.value">
                        <option value="">-- 请先选择应用 --</option>
                        <?php foreach($appList as $app): ?>
                            <option value="<?=$app['id']?>" <?=($appFilter === $app['id']) ? 'selected' : ''?>><?=htmlspecialchars($app['app_name'])?></option>
                        <?php endforeach; ?>
                     </select>
                </div>
            </div>

            <?php if ($appFilter !== null || !empty($_GET['q'])): ?>
            
                <div class="nav-segment" style="margin-bottom: 24px;">
                    <a href="?tab=list&filter=all<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='all'?'active':''?>">全部</a>
                    <a href="?tab=list&filter=unused<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='unused'?'active':''?>">未激活</a>
                    <a href="?tab=list&filter=active<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='active'?'active':''?>">已激活</a>
                    <a href="?tab=list&filter=banned<?=($appFilter!==null?'&app_id='.$appFilter:'')?>" class="nav-pill <?=$filterStr=='banned'?'active':''?>">已封禁</a>
                </div>

                <div class="panel">
                    <form id="batchForm" method="POST">
                        <input type="hidden" name="csrf_token" value="<?=$csrf_token?>">
                        <div class="panel-head">
                            <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;width:100%;">
                                <input type="text" placeholder="搜索卡密、备注或设备指纹..." value="<?=$_GET['q']??''?>" class="form-control" style="margin:0;min-width:200px;flex:1;" onkeydown="if(event.key==='Enter'){event.preventDefault();window.location='?tab=list&q='+this.value;}">
                                <a href="?tab=list" class="btn btn-icon" style="background:#f1f5f9;color:#64748b;"><i class="fas fa-sync"></i></a>
                                <a href="?tab=create" class="btn btn-primary btn-icon"><i class="fas fa-plus"></i></a>
                            </div>
                            <div style="width:100%; display:flex; gap:8px; margin-top:16px; overflow-x:auto; padding-bottom:4px;">
                                <button type="submit" name="batch_export" value="1" class="btn" style="background:#6366f1;color:white;flex-shrink:0;">导出</button>
                                <button type="button" onclick="submitBatch('batch_unbind')" class="btn" style="background:#f59e0b;color:white;flex-shrink:0;">解绑</button>
                                <button type="button" onclick="batchAddTime()" class="btn" style="background:#10b981;color:white;flex-shrink:0;">加时</button>
                                <button type="button" onclick="submitBatch('batch_delete')" class="btn btn-danger" style="flex-shrink:0;">删除</button>
                            </div>
                        </div>
                        <input type="hidden" name="add_hours" id="addHoursInput">
                        <div class="table-responsive">
                            <table>
                                <thead><tr><th style="width:40px;text-align:center;"><input type="checkbox" onclick="toggleAll(this)" style="accent-color:var(--primary);"></th><th>应用</th><th>卡密代码</th><th>类型</th><th>状态</th><th>绑定设备</th><th>备注</th><th>操作</th></tr></thead>
                                <tbody>
                                    <?php foreach($cardList as $card): ?>
                                    <tr>
                                        <td style="text-align:center;"><input type="checkbox" name="ids[]" value="<?=$card['id']?>" class="row-check" style="accent-color:var(--primary);"></td>
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
                                        <td style="display:flex;gap:6px;">
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
                                    <?php if(empty($cardList)): ?><tr><td colspan="8" style="text-align:center;padding:40px;color:#94a3b8;">暂无符合条件的卡密</td></tr><?php endif; ?>
                                </tbody>
                            </table>
                        </div>

                        <div class="pagination">
                            <select class="form-control" style="width:auto; margin:0 12px 0 0;" onchange="window.location.href='?tab=list&filter=<?=$filterStr?>&page=1&limit='+this.value+'<?=isset($_GET['q'])?'&q='.htmlspecialchars($_GET['q']):''?><?=($appFilter!==null?'&app_id='.$appFilter:'')?>'">
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
            <div class="panel" style="max-width:600px; margin:20px auto;">
                <div class="panel-head"><span class="panel-title">批量生成卡密</span></div>
                <div style="padding:28px;">
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
                        <div style="display:flex;gap:12px;">
                            <div style="flex:1;">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">前缀 (选填)</label>
                                <input type="text" name="pre" class="form-control">
                            </div>
                            <div style="flex:2;">
                                <label style="display:block;margin-bottom:8px;font-weight:600;font-size:13px;">备注</label>
                                <input type="text" name="note" class="form-control">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width:100%; margin-top:8px;">确认生成</button>
                    </form>
                </div>
            </div>
        <?php endif; ?>

        <?php if($tab == 'logs'): ?>
            <div class="panel" style="margin-top:20px;">
                <div class="panel-head"><span class="panel-title">鉴权审计日志</span></div>
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
            <div class="panel" style="max-width:500px; margin:20px auto;">
                <div class="panel-head"><span class="panel-title">修改管理员密码</span></div>
                <div style="padding:28px;">
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

<div id="toast" class="toast"><i class="fas fa-check-circle"></i> 已复制到剪贴板</div>

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
                datasets: [{ data: Object.values(typeData), backgroundColor: ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'], borderWidth: 0 }]
            },
            options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right', labels: { usePointStyle: true, boxWidth: 8, font: {size: 11, family: "'Outfit', sans-serif"} } } } }
        });
    });
    <?php endif; ?>

    (function(){
        const currentTabId = '<?=$tab?>';
        const currentTabTitle = '<?=$currentTitle?>';
        let openTabs = JSON.parse(localStorage.getItem('admin_tabs') || '[]');
        
        if (openTabs.length === 0 || openTabs[0].id !== 'dashboard') {
            openTabs = openTabs.filter(t => t.id !== 'dashboard'); 
            openTabs.unshift({id: 'dashboard', title: '首页'});
        }

        const exists = openTabs.find(t => t.id === currentTabId);
        if (!exists) { openTabs.push({id: currentTabId, title: currentTabTitle}); }
        localStorage.setItem('admin_tabs', JSON.stringify(openTabs));

        const container = document.getElementById('tabs-container');
        let html = '';
        openTabs.forEach(t => {
            const isActive = (t.id === currentTabId) ? 'active' : '';
            const closeBtn = (t.id === 'dashboard') ? '' : `<i class="fas fa-times" onclick="closeTab(event, '${t.id}')" style="font-size:10px; margin-left:4px; opacity:0.6;"></i>`;
            html += `<a href="?tab=${t.id}" class="chrome-tab ${isActive}">${t.title} ${closeBtn}</a>`;
        });
        container.innerHTML = html;

        window.closeTab = function(e, tabId) {
            e.preventDefault(); e.stopPropagation();
            openTabs = openTabs.filter(t => t.id !== tabId);
            localStorage.setItem('admin_tabs', JSON.stringify(openTabs));
            if (tabId === currentTabId) { window.location.href = '?tab=dashboard'; } 
            else { e.target.closest('.chrome-tab').remove(); }
        };
    })();
</script>
</body>
</html>
