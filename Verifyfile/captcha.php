<?php
// Verifyfile/captcha.php
session_start();

$code = '';
for ($i = 0; $i < 4; $i++) {
    // 使用 random_int 替代 mt_rand 增加安全性
    $code .= dechex(random_int(0, 15)); 
}
$_SESSION['captcha_code'] = strtoupper($code);

$width = 100;
$height = 42;
$image = imagecreatetruecolor($width, $height);

$bg = imagecolorallocate($image, 30, 41, 59);
$text_color = imagecolorallocate($image, 255, 255, 255);
$line_color = imagecolorallocate($image, 59, 130, 246);

imagefill($image, 0, 0, $bg);

for ($i = 0; $i < 3; $i++) {
    imageline($image, 0, rand(0, $height), $width, rand(0, $height), $line_color);
}

for ($i = 0; $i < 50; $i++) {
    imagesetpixel($image, rand(0, $width), rand(0, $height), $line_color);
}

imagestring($image, 5, 30, 13, $_SESSION['captcha_code'], $text_color);

header('Content-Type: image/png');
imagepng($image);
imagedestroy($image);
?>
