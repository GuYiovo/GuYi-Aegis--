<?php
require_once 'config.php'; // 必须放在第一行！它会负责检查是否安装，没安装会自动跳转

// ...
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>ACCESS CONTROL | 权限验证</title>
    <link rel="icon" href="backend/logo.png" type="image/png">
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <link href="assets/css/remixicon.css" rel="stylesheet">
    
    <style>
        :root {
            --glass-surface: rgba(255, 255, 255, 0.65);
            --glass-border: rgba(255, 255, 255, 0.4);
            --glass-highlight: rgba(255, 255, 255, 0.8);
            --glass-shadow: rgba(0, 0, 0, 0.05);
            --primary-accent: #6366f1;
            --secondary-accent: #ec4899;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --input-bg: rgba(255, 255, 255, 0.4);
            --success: #10b981;
            --error: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; height: 100vh; display: flex; justify-content: center; align-items: center; background-color: #f3f4f6; overflow: hidden; position: relative; }
        .ambient-light { position: absolute; width: 100%; height: 100%; z-index: 0; overflow: hidden; background: #eef2ff; }
        .blob { position: absolute; filter: blur(80px); opacity: 0.8; animation: float 10s infinite alternate cubic-bezier(0.4, 0, 0.2, 1); }
        .blob-1 { top: -10%; left: -10%; width: 50vw; height: 50vw; background: linear-gradient(135deg, #c7d2fe 0%, #818cf8 100%); border-radius: 40% 60% 70% 30% / 40% 50% 60% 50%; }
        .blob-2 { bottom: -10%; right: -10%; width: 60vw; height: 60vw; background: linear-gradient(135deg, #fbcfe8 0%, #f472b6 100%); border-radius: 60% 40% 30% 70% / 60% 30% 70% 40%; animation-delay: -5s; }
        @keyframes float { 0% { transform: translate(0, 0) rotate(0deg); } 100% { transform: translate(30px, 50px) rotate(10deg); } }
        .noise-overlay { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; pointer-events: none; opacity: 0.04; background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E"); }
        .glass-card { position: relative; z-index: 10; width: 90%; max-width: 420px; background: var(--glass-surface); backdrop-filter: blur(40px) saturate(180%); -webkit-backdrop-filter: blur(40px) saturate(180%); border: 1px solid var(--glass-border); border-top: 1px solid var(--glass-highlight); border-radius: 32px; padding: 48px 36px; box-shadow: 0 30px 60px -12px rgba(50, 50, 93, 0.15), 0 18px 36px -18px rgba(0, 0, 0, 0.1), inset 0 0 0 1px rgba(255, 255, 255, 0.2); animation: cardEntrance 1s cubic-bezier(0.2, 0.8, 0.2, 1); }
        @keyframes cardEntrance { from { opacity: 0; transform: translateY(40px) scale(0.95); } to { opacity: 1; transform: translateY(0) scale(1); } }
        .header { display: flex; flex-direction: column; align-items: center; margin-bottom: 40px; }
        .icon-box { width: 64px; height: 64px; background: linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.2) 100%); border: 1px solid rgba(255,255,255,0.8); border-radius: 20px; display: flex; align-items: center; justify-content: center; margin-bottom: 20px; box-shadow: 0 15px 35px -10px rgba(99, 102, 241, 0.3); font-size: 28px; color: var(--primary-accent); }
        h1 { font-size: 22px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.02em; margin-bottom: 8px; }
        .subtitle { font-size: 13px; color: var(--text-secondary); font-weight: 500; background: rgba(255,255,255,0.5); padding: 6px 16px; border-radius: 20px; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; }
        .subtitle:hover { background: rgba(255,255,255,0.8); border-color: rgba(99, 102, 241, 0.2); color: var(--primary-accent); transform: translateY(-1px); }
        .input-group { position: relative; margin-bottom: 24px; }
        .input-container { position: relative; background: var(--input-bg); border-radius: 16px; transition: all 0.3s ease; border: 2px solid transparent; display: flex; align-items: center; }
        .input-container:focus-within { background: #fff; border-color: rgba(99, 102, 241, 0.3); box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1); }
        .input-icon { padding-left: 18px; color: #94a3b8; font-size: 20px; transition: color 0.3s; }
        .input-container:focus-within .input-icon { color: var(--primary-accent); }
        input { width: 100%; padding: 18px 16px; background: transparent; border: none; font-family: 'Monaco', 'Menlo', monospace; font-size: 15px; color: var(--text-primary); letter-spacing: 1.5px; font-weight: 600; }
        input::placeholder { font-family: 'Inter', sans-serif; letter-spacing: 0; color: #94a3b8; font-weight: 400; }
        .status-message { min-height: 24px; margin-bottom: 20px; font-size: 13px; text-align: center; font-weight: 500; opacity: 0; transform: translateY(-5px); transition: all 0.3s; }
        .status-message.active { opacity: 1; transform: translateY(0); }
        .status-message.error { color: var(--error); }
        .status-message.success { color: var(--success); }
        button { width: 100%; padding: 18px; border: none; border-radius: 16px; background: linear-gradient(135deg, var(--primary-accent), #4f46e5); color: white; font-size: 16px; font-weight: 600; cursor: pointer; position: relative; overflow: hidden; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 10px 20px -5px rgba(99, 102, 241, 0.4); }
        button::after { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: 0.5s; }
        button:hover::after { left: 100%; }
        button:hover { transform: translateY(-2px); box-shadow: 0 15px 30px -5px rgba(99, 102, 241, 0.5); }
        button:active { transform: translateY(0); }
        .loader { display: none; width: 20px; height: 20px; border: 2px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: #fff; animation: spin 0.8s linear infinite; margin: 0 auto; }
        button.loading span { display: none; }
        button.loading .loader { display: block; }
        .footer { margin-top: 32px; display: flex; justify-content: space-between; align-items: center; padding-top: 24px; border-top: 1px solid rgba(0,0,0,0.06); }
        .copyright { font-size: 12px; color: var(--text-secondary); opacity: 0.8; }
        .switch-group { display: flex; align-items: center; gap: 10px; cursor: pointer; }
        .switch-text { font-size: 12px; color: var(--text-secondary); font-weight: 500; }
        .switch-input { display: none; }
        .switch-slider { width: 36px; height: 20px; background-color: rgba(203, 213, 225, 0.5); border-radius: 20px; position: relative; transition: 0.3s; box-shadow: inset 0 2px 4px rgba(0,0,0,0.05); }
        .switch-slider::before { content: ""; position: absolute; width: 16px; height: 16px; left: 2px; bottom: 2px; background: white; border-radius: 50%; transition: 0.3s cubic-bezier(0.4, 0.0, 0.2, 1); box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .switch-input:checked + .switch-slider { background-color: var(--primary-accent); }
        .switch-input:checked + .switch-slider::before { transform: translateX(16px); }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes shake { 0%, 100% { transform: translateX(0); } 20%, 60% { transform: translateX(-5px); } 40%, 80% { transform: translateX(5px); } }
        .shake { animation: shake 0.4s ease-in-out; }
    </style>
</head>
<body>

    <div class="ambient-light">
        <div class="blob blob-1"></div>
        <div class="blob blob-2"></div>
    </div>
    
    <div class="noise-overlay"></div>

    <div class="glass-card">
        <div id="login-view">
            <div class="header">
                <div class="icon-box">
                    <i class="ri-shield-keyhole-line"></i>
                </div>
                <h1>GuYi Access Verification</h1>
                <div class="subtitle" onclick="copyGroup()">
                    <i class="ri-group-line" style="margin-right:4px; vertical-align: bottom;"></i>
                    官方群: 562807728
                </div>
            </div>
            
            <form id="auth-form">
                <div class="input-group">
                    <div class="input-container">
                        <i class="ri-qr-code-line input-icon"></i>
                        <input type="text" id="card-key" placeholder="XXXX XXXX XXXX XXXX" 
                               autocomplete="off" autocorrect="off" autocapitalize="characters" maxlength="19">
                    </div>
                </div>
                
                <div id="status-msg" class="status-message"></div>
                
                <button type="submit" id="btn-submit">
                    <span>立即验证</span>
                    <div class="loader"></div>
                </button>
            </form>
            
            <div class="footer">
                <div class="copyright">© 2026 SecureSys</div>
                <label class="switch-group">
                    <span class="switch-text">记住卡密</span>
                    <input type="checkbox" id="remember-me" class="switch-input">
                    <div class="switch-slider"></div>
                </label>
            </div>
        </div>
    </div>

    <script src="assets/js/main.js"></script>
</body>
</html>
