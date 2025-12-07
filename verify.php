<?php
// verify.php - 前端验证处理
require_once 'config.php';
require_once 'database.php';

session_start();
header('Content-Type: application/json; charset=utf-8');

// 接收 JSON 或 POST
$input = file_get_contents('php://input');
$data = json_decode($input, true) ?? $_POST;

$cardCode = trim($data['card_code'] ?? '');
$deviceHash = trim($data['device_hash'] ?? '');

if (empty($cardCode)) {
    echo json_encode(['success' => false, 'message' => '请输入卡密']);
    exit;
}

// 自动补全设备指纹
if (empty($deviceHash)) {
    $deviceHash = md5($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
}

try {
    $db = new Database();
    $result = $db->verifyCard($cardCode, $deviceHash);
    
    if ($result['success']) {
        $_SESSION['verified'] = true;
        $_SESSION['card_code'] = $cardCode;
        echo json_encode(['success' => true, 'message' => $result['message']]);
    } else {
        echo json_encode(['success' => false, 'message' => $result['message']]);
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'message' => '系统维护中']);
}
?>
