const UI = {
    card: document.querySelector('.glass-card'),
    input: document.getElementById('card-key'),
    form: document.getElementById('auth-form'),
    btn: document.getElementById('btn-submit'),
    msg: document.getElementById('status-msg'),
    remember: document.getElementById('remember-me'),
    
    showMsg: (text, type) => {
        UI.msg.textContent = text;
        if(type === 'success') {
            UI.card.style.transform = 'scale(0.98)';
            UI.card.style.opacity = '0.9';
        } else {
            UI.card.style.transform = 'scale(1)';
            UI.card.style.opacity = '1';
        }
        UI.msg.className = `status-message active ${type}`;
        if(type === 'error') {
            UI.input.parentElement.classList.add('shake');
            setTimeout(()=>UI.input.parentElement.classList.remove('shake'), 500);
            navigator.vibrate?.(200);
        }
    },
    
    resetMsg: () => {
        UI.msg.className = 'status-message';
        UI.card.style.transform = 'scale(1)';
        UI.card.style.opacity = '1';
    },

    setLoading: (isLoading) => {
        if(isLoading) {
            UI.btn.classList.add('loading');
            UI.btn.disabled = true;
        } else {
            UI.btn.classList.remove('loading');
            UI.btn.disabled = false;
        }
    }
};

function md5(input) {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
}

UI.input.addEventListener('input', (e) => {
    let v = e.target.value.replace(/\s+/g, '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
    let parts = [];
    for(let i=0; i<v.length; i+=4) parts.push(v.substring(i, i+4));
    e.target.value = parts.join(' ');
});

window.copyGroup = () => {
    navigator.clipboard.writeText("562807728").then(() => UI.showMsg("群号已复制，快去加入吧", "success")).catch(() => UI.showMsg("复制失败", "error"));
};

if(localStorage.getItem('saved_key')) {
    UI.input.value = localStorage.getItem('saved_key');
    UI.remember.checked = true;
}

UI.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const key = UI.input.value.replace(/\s+/g, '');
    UI.resetMsg();
    if(key.length < 10) { UI.showMsg("卡密格式看起来不对", "error"); return; }

    UI.setLoading(true);

    let deviceHash = localStorage.getItem('device_fingerprint');
    if (!deviceHash) {
        const fingerprint = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            screen: `${screen.width}x${screen.height}`,
            random: Math.random().toString(36).substr(2, 9)
        };
        deviceHash = md5(JSON.stringify(fingerprint));
        localStorage.setItem('device_fingerprint', deviceHash);
    }

    try {
        const response = await fetch('verify.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ card_code: key, device_hash: deviceHash })
        });
        
        const result = await response.json();
        
        if(result.success) {
            UI.showMsg(result.message, "success");
            if(UI.remember.checked) localStorage.setItem('saved_key', UI.input.value);
            else localStorage.removeItem('saved_key');

            // --- 核心修复开始：解决iOS 17跳转弹出地址栏问题 ---
            setTimeout(() => {
                fetch("index1.php")
                .then(r => r.text())
                .then(html => {
                    // 1. 偷偷修改URL，让返回键逻辑正常（看起来像跳了，实际没跳）
                    window.history.replaceState(null, "", "index1.php");
                    
                    // 2. 擦除当前文档，直接写入新页面代码
                    // 浏览器认为还是在同一个页面，所以不会弹地址栏
                    document.open();
                    document.write(html);
                    document.close();
                })
                .catch(err => {
                    // 如果获取失败（如断网），降级使用普通跳转
                    window.location.replace("index1.php");
                });
            }, 1200);
            // --- 核心修复结束 ---

        } else {
            UI.showMsg(result.message, "error");
            UI.setLoading(false);
        }
    } catch (error) {
        console.error(error);
        UI.showMsg("网络错误", "error");
        UI.setLoading(false);
    }
});

setTimeout(() => UI.input.focus(), 100);

(function() {
    document.addEventListener('contextmenu', event => event.preventDefault());
    document.onkeydown = function(e) {
        if (e.keyCode == 123) return false;
        if (e.ctrlKey && e.shiftKey && (e.keyCode == 73 || e.keyCode == 74)) return false; 
        if (e.ctrlKey && e.keyCode == 85) return false; 
    };
})();
