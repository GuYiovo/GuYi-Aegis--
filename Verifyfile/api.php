<?php
// Verifyfile/api.php - Secure API Endpoint
require_once '../config.php';
require_once '../database.php';

// 安全响应头
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *'); // 生产环境建议指定具体域名
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// 简单的 IP 速率限制 (Rate Limiting)
function checkRateLimit($ip) {
    $limit = 60; // 每分钟60次
    $file = sys_get_temp_dir() . '/ent_ratelimit_' . md5($ip);
    $data = file_exists($file) ? json_decode(file_get_contents($file), true) : ['count'=>0, 'time'=>time()];
    
    if (time() - $data['time'] > 60) {
        $data = ['count' => 1, 'time' => time()];
    } else {
        $data['count']++;
        if ($data['count'] > $limit) return false;
    }
    file_put_contents($file, json_encode($data));
    return true;
}

$ip = $_SERVER['REMOTE_ADDR'];
if (!checkRateLimit($ip)) {
    http_response_code(429);
    echo json_encode(['code' => 429, 'msg' => 'Too many requests. Please try again later.']);
    exit;
}

// 数据处理
$data = [];
$json_input = file_get_contents('php://input');
if (!empty($json_input)) {
    $data = json_decode($json_input, true) ?? [];
} 
$data = array_merge($_GET, $_POST, $data);

$card_code = isset($data['card']) ? trim($data['card']) : (isset($data['key']) ? trim($data['key']) : '');
$device_hash = isset($data['device']) ? trim($data['device']) : (isset($data['machine_id']) ? trim($data['machine_id']) : '');
$app_key = isset($data['app_key']) ? trim($data['app_key']) : '';

if (empty($card_code)) {
    echo json_encode(['code' => 400, 'msg' => 'Missing parameter: card']);
    exit;
}

if (empty($device_hash)) {
    $device_hash = md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']); 
}

try {
    $db = new Database();
    $db->cleanupExpiredDevices();
    
    // 增加 app_key 参数传递
    $result = $db->verifyCard($card_code, $device_hash, $app_key);
    
    if ($result['success']) {
        $expire_timestamp = strtotime($result['expire_time']);
        $remaining_seconds = max(0, $expire_timestamp - time());

        echo json_encode([
            'code' => 200,
            'msg'  => 'OK',
            'data' => [
                'status' => 'active',
                'expire_time' => $result['expire_time'],
                'remaining_seconds' => $remaining_seconds,
                'device_id' => $device_hash
            ]
        ]);
    } else {
        echo json_encode([
            'code' => 403,
            'msg'  => $result['message'],
            'data' => null
        ]);
    }

} catch (Exception $e) {
    // 生产环境不返回具体错误详情，防止泄密
    echo json_encode([
        'code' => 500,
        'msg'  => 'Internal Server Error'
    ]);
}
?>
