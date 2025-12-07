<?php
// Verifyfile/captcha.php - 生成验证码图片
session_start();

// 生成随机码
$code = '';
for ($i = 0; $i < 4; $i++) {
    $code .= dechex(mt_rand(0, 15)); // 0-F 十六进制
}
$_SESSION['captcha_code'] = strtoupper($code);

// 创建图片
$width = 100;
$height = 42;
$image = imagecreatetruecolor($width, $height);

// 颜色定义
$bg = imagecolorallocate($image, 30, 41, 59); // 与后台背景一致的深蓝
$text_color = imagecolorallocate($image, 255, 255, 255); // 白色文字
$line_color = imagecolorallocate($image, 59, 130, 246); // 蓝色干扰线

// 填充背景
imagefill($image, 0, 0, $bg);

// 添加干扰线
for ($i = 0; $i < 3; $i++) {
    imageline($image, 0, rand(0, $height), $width, rand(0, $height), $line_color);
}

// 添加噪点
for ($i = 0; $i < 50; $i++) {
    imagesetpixel($image, rand(0, $width), rand(0, $height), $line_color);
}

// 写入文字
imagestring($image, 5, 30, 13, $_SESSION['captcha_code'], $text_color);

// 输出图片
header('Content-Type: image/png');
imagepng($image);
imagedestroy($image);
?>
