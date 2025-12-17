<?php
// Verifyfile/api.php - 强制免卡密获取变量版
require_once '../config.php';
require_once '../database.php';

// 调试标记：确认文件是否更新成功
header('X-Debug-Version: 2.1-Fixed'); 
header('Content-Type: application/json; charset=utf-8');

// 1. 获取参数
$json_input = file_get_contents('php://input');
$data = [];
if (!empty($json_input)) $data = json_decode($json_input, true) ?? [];
$data = array_merge($_GET, $_POST, $data);

// [修复开始] ==========================================================
// 问题原因：易语言模块发送的是 card_code，而原代码只读取 card。
// 导致 $card_code 为空，从而误进入了“场景A(获取公开变量)”，返回了200状态码。
// 修复方法：优先读取 card_code 和 device_hash，兼容旧版参数。

$card_code = !empty($data['card_code']) ? trim($data['card_code']) : (isset($data['card']) ? trim($data['card']) : '');
$app_key   = isset($data['app_key']) ? trim($data['app_key']) : '';
$device    = !empty($data['device_hash']) ? trim($data['device_hash']) : (isset($data['device']) ? trim($data['device']) : '');
// [修复结束] ==========================================================

// 2. 逻辑分流
try {
    $db = new Database();

    // ==========================================
    // 场景 A：无卡密模式 (只看 AppKey) -> 取变量
    // ==========================================
    if (empty($card_code) && !empty($app_key)) {
        
        // 查找 AppKey 对应的应用
        $appInfo = $db->getAppIdByKey($app_key);
        
        if (!$appInfo) {
            echo json_encode(['code' => 403, 'msg' => 'AppKey 错误或不存在']);
            exit;
        }

        // 获取公开变量
        // 注意：这里只会返回勾选了 "公开" 的变量
        $raw_vars = $db->getAppVariables($appInfo['id'], true); 
        
        $variables = [];
        foreach ($raw_vars as $v) {
            $variables[$v['key_name']] = $v['value'];
        }

        // [优化] 即使没有变量，只要是获取配置模式，也返回标准结构，避免客户端误判
        if (empty($variables)) {
             echo json_encode(['code' => 200, 'msg' => 'OK', 'data' => ['variables' => null, 'tips' => '连接成功，但该应用下没有公开变量']]);
             exit;
        }

        echo json_encode([
            'code' => 200,
            'msg' => 'OK',
            'data' => [
                'variables' => $variables
            ]
        ]);
        exit; // <--- 关键：直接结束，不走下面的卡密验证
    }

    // ==========================================
    // 场景 B：卡密登录模式
    // ==========================================
    if (empty($card_code)) {
        echo json_encode(['code' => 400, 'msg' => '请输入卡密']);
        exit;
    }

    if (empty($device)) $device = md5($_SERVER['REMOTE_ADDR']);

    $result = $db->verifyCard($card_code, $device, $app_key);
    
    if ($result['success']) {
        // 登录成功，返回所有变量
        $variables = [];
        if (isset($result['app_id']) && $result['app_id'] > 0) {
            $raw_vars = $db->getAppVariables($result['app_id'], false);
            foreach ($raw_vars as $v) $variables[$v['key_name']] = $v['value'];
        }

        echo json_encode(['code' => 200, 'msg' => 'OK', 'data' => ['expire_time' => $result['expire_time'], 'variables' => $variables]]);
    } else {
        // 登录失败，返回 403，客户端将识别为失败
        echo json_encode(['code' => 403, 'msg' => $result['message'], 'data' => null]);
    }

} catch (Exception $e) {
    // 捕获数据库错误（比如 database.php 没更新导致的错误）
    echo json_encode(['code' => 500, 'msg' => 'Server Error: ' . $e->getMessage()]);
}
?>
