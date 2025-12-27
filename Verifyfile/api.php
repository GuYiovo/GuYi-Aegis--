<?php
// Verifyfile/api.php - 安全增强版
require_once '../config.php';
require_once '../database.php';

header('Content-Type: application/json; charset=utf-8');

$rate_ip = $_SERVER['REMOTE_ADDR'];
$rate_file = sys_get_temp_dir() . '/rate_' . md5($rate_ip);
$current_minute = date('Hi'); // 格式 1425 (小时分钟)

$rate_data = @json_decode(file_get_contents($rate_file), true);
if ($rate_data && $rate_data['time'] == $current_minute) {
    if ($rate_data['count'] > 60) {
        http_response_code(429);
        die(json_encode(['code' => 429, 'msg' => 'Too Many Requests - 请稍后重试']));
    }
    $rate_data['count']++;
} else {
    $rate_data = ['time' => $current_minute, 'count' => 1];
}
file_put_contents($rate_file, json_encode($rate_data));
// ------------------------------------------------

// 1. 获取参数
$json_input = file_get_contents('php://input');
$data = [];
if (!empty($json_input)) $data = json_decode($json_input, true) ?? [];
$data = array_merge($_GET, $_POST, $data);

// 参数兼容处理
$card_code = !empty($data['card_code']) ? trim($data['card_code']) : (isset($data['card']) ? trim($data['card']) : '');
$app_key   = isset($data['app_key']) ? trim($data['app_key']) : '';
$device    = !empty($data['device_hash']) ? trim($data['device_hash']) : (isset($data['device']) ? trim($data['device']) : '');

try {
    $db = new Database();

    if (empty($card_code) && !empty($app_key)) {
        $appInfo = $db->getAppIdByKey($app_key);
        
        if (!$appInfo) {
            echo json_encode(['code' => 403, 'msg' => 'AppKey 错误或不存在']);
            exit;
        }

        $raw_vars = $db->getAppVariables($appInfo['id'], true); 
        $variables = [];
        foreach ($raw_vars as $v) $variables[$v['key_name']] = $v['value'];

        echo json_encode(['code' => 200, 'msg' => 'OK', 'data' => ['variables' => $variables ?: null]]);
        exit;
    }

    if (empty($card_code)) {
        echo json_encode(['code' => 400, 'msg' => '请输入卡密']);
        exit;
    }

    if (empty($device)) $device = md5($_SERVER['REMOTE_ADDR']);

    $result = $db->verifyCard($card_code, $device, $app_key);
    
    if ($result['success']) {
        $variables = [];
        if (isset($result['app_id']) && $result['app_id'] > 0) {
            $raw_vars = $db->getAppVariables($result['app_id'], false);
            foreach ($raw_vars as $v) $variables[$v['key_name']] = $v['value'];
        }

        echo json_encode(['code' => 200, 'msg' => 'OK', 'data' => ['expire_time' => $result['expire_time'], 'variables' => $variables]]);
    } else {
        echo json_encode(['code' => 403, 'msg' => $result['message'], 'data' => null]);
    }

} catch (Exception $e) {
    echo json_encode(['code' => 500, 'msg' => 'Server Error: ' . $e->getMessage()]);
}
?>
