# All_Stars

All_Stars 是一个面向 **Web 相关开源项目**的漏洞挖掘与验证仓库。根据 GitHub 仓库的项目描述、README 与功能定位，筛选 Web Server、Web 应用、CMS、API 服务等类别中 **Stars 不少于 1,000、具有一定社区影响力**的项目作为候选目标，使用 [xiaomin_codex](https://github.com/duskto/xiaomin_codex) 提供的漏洞挖掘 skill 进行分析与复核，再部署目标项目开展动态验证，最终归档报告、复核材料及 PoC / EXP。

## 项目筛选要求

- **项目描述与功能定位**：根据 GitHub 仓库的项目描述、README 和 Topics 判断项目用途，筛选 Web Server、Web 应用、CMS、Web 框架及插件、API 服务等 Web 相关项目。
- **关注度与影响力**：以 GitHub Stars 不少于 1,000、具有一定社区影响力作为候选目标的筛选条件，结合实际使用场景和维护情况安排研究优先级。
- **目标范围**：围绕浏览器或 HTTP/HTTPS 可触达的功能开展分析，关注服务端入口、管理后台、开放接口及包含 Web 功能的组件。
- **研究内容**：分析认证与权限控制、输入处理、文件操作、模板渲染、反序列化、服务端请求等环节中的安全问题。
- **筛选记录**：记录上游仓库链接、项目描述、Web 功能、筛选时的 Stars 数与日期、测试版本或 commit，以及部署条件。

上述要求用于候选目标筛选；具体挖掘进度和验证结果以对应项目的报告为准。

## 挖掘与验证方法

本项目使用 [xiaomin_codex](https://github.com/duskto/xiaomin_codex) 中的 [vuln-hunt-memory-driven](https://github.com/duskto/xiaomin_codex/blob/master/skills/vuln-hunt-memory-driven/SKILL.md) skill。安装与配置参见 [xiaomin_codex README](https://github.com/duskto/xiaomin_codex/blob/master/README.md)。

整体方法为：**使用 xiaomin_codex 挖掘与复核，再部署目标项目进行验证。**

1. **筛选并准备目标**  
   根据 GitHub 项目描述和功能定位，选择 Stars 不少于 1,000、具有一定社区影响力的 Web Server、Web 应用、CMS 或 API 服务等项目，获取对应源码，固定测试版本或 commit，梳理运行依赖、配置和待分析功能。

2. **使用 xiaomin_codex 挖掘**  
   按 skill 的工作流识别攻击面与认证链路，分析外部输入到敏感操作的数据流，定位候选漏洞并记录代码位置、触发条件和潜在影响。

3. **使用 xiaomin_codex 验证与复核**  
   执行 skill 的验证和独立挑战复核，检查输入是否可控、调用路径是否可达、认证与权限前提是否成立，以及现有防护是否影响候选结论。记录复核结果、证据和仍待验证的问题。

4. **部署目标项目并动态验证**  
   在本地或测试环境中部署对应版本的目标项目及必要依赖，按照实际入口通过 HTTP 请求或浏览器操作进行复现。记录请求与响应、日志或截图，核对实际结果与预期影响；涉及额外配置、示例程序或非默认条件时，在报告中明确说明。

5. **整理结论并归档**  
   将漏洞分析、复核结论、部署步骤和动态验证证据整理到项目的 `reports/` 目录，将独立 PoC / EXP 保存到 `exp/` 目录。对未复现、环境受阻或被排除的候选，记录已完成的检查及原因。

### 验证记录要求

每项候选漏洞的报告应包含：

- **目标信息**：项目来源、测试版本或 commit、相关文件和代码位置。
- **触发前提**：认证状态、所需权限、配置、依赖与输入条件。
- **skill 复核结果**：xiaomin_codex 的分析结论、复核依据和未解决的问题。
- **部署与复现证据**：环境信息、部署步骤、复现步骤、预期结果、实际结果及相关日志。
- **最终状态**：明确标记待部署验证、已部署验证、环境受阻、未复现或已排除，并说明依据。

skill 复核结论与部署验证结果分别记录。标记为“已部署验证”时，应具备对应版本、实际运行环境和可复现证据；已有归档材料的验证状态以各报告中的记录为准。

## 仓库内容

| 路径 | 说明 |
| --- | --- |
| `仓库所有者_仓库名/reports/` | 漏洞报告、复核材料、部署验证记录及 PoC / EXP 说明。 |
| `仓库所有者_仓库名/exp/` | 独立 PoC / EXP 文件。 |
| [manifest.json](manifest.json) | 已归档文件的路径、原始来源、大小与 SHA-256 记录。 |

## 已归档项目

本目录归档原工作目录内各项目筛选保留的报告和 EXP 文件。目录统一按“仓库所有者_仓库名”命名，已核对项目内的 Git 远程配置、README 或原始项目路径记录；仓库所有者不代表漏洞报告作者。

| 仓库所有者_仓库名 | 报告/复核文件数 | EXP 文件数 |
| --- | ---: | ---: |
| [aFarkas_webshim](aFarkas_webshim/) | 2 | 3 |
| [CSAILVision_LabelMeAnnotationTool](CSAILVision_LabelMeAnnotationTool/) | 4 | 1 |
| [fossasia_fossasia11-drupal](fossasia_fossasia11-drupal/) | 2 | 1 |
| [zelon88_HRConvert2](zelon88_HRConvert2/) | 3 | 1 |
| [kubesphere_kubeeye](kubesphere_kubeeye/) | 1 | 1 |
| [unacms_UNA](unacms_UNA/) | 1 | 2 |
| [phpList_phplist3](phpList_phplist3/) | 1 | 1 |

## 归档与溯源说明

- 每个项目下 reports/ 保存报告、复核材料和 EXP 说明；exp/ 保存已有的独立 EXP 文件。
- 文件按原始字节复制；同项目、同类别、同名且 SHA-256 相同的副本合并，所有来源记入 manifest.json。
- manifest.json 记录归档路径、原始来源、大小和 SHA-256；压缩包来源以 压缩包路径::内部路径 表示，Windows 来源路径相对于原工作目录；wsl:Debian:/... 表示 Debian 内的绝对来源路径。
- 原项目目录和压缩包保持原样；未复制完整项目源码、运行状态文件、缓存或开发过程计划。
- 历史归档过程未运行或修改 EXP，未验证漏洞；报告中的原始相对路径保留，可能需要结合来源清单查找。

### 目录名称核对依据

未注明 WSL 的路径相对于原工作目录：

| 归档目录 | 项目内依据 |
| --- | --- |
| `aFarkas_webshim` | `aFarkas_webshim/webshim.zip::171_aFarkas_webshim/readme.md` 的下载地址为 `github.com/aFarkas/webshim/releases/latest`。 |
| `CSAILVision_LabelMeAnnotationTool` | `CSAILVision_LabelMeAnnotationTool/102_CSAILVision_LabelMeAnnotationTool/102_CSAILVision_LabelMeAnnotationTool/README.md` 的克隆地址为 `github.com/CSAILVision/LabelMeAnnotationTool.git`。 |
| `fossasia_fossasia11-drupal` | `fossasia11-drupal/fossasia11_drupal/README.md` 标题为 `fossasia11-drupal`；同目录 `context_snapshot.json` 的 `target_dir` 为 `D:\破壳项目\157_fossasia_fossasia11-drupal`，据此确认所有者标识为 `fossasia`。 |
| `zelon88_HRConvert2` | `zelon88_HRConvert2/112_zelon88_HRConvert2/112_zelon88_HRConvert2/README.md` 的安装文档地址位于 `github.com/zelon88/HRConvert2`。 |
| `kubesphere_kubeeye` | WSL Debian `~/漏挖复审/908-kubeeye` 的 Git origin 为 `https://github.com/kubesphere/kubeeye.git`，README 和 go.mod 一致。 |
| `unacms_UNA` | WSL Debian `~/漏挖复审/UNA` 的 Git origin 为 `https://github.com/unacms/UNA.git`；目录大小写按该地址保留。 |
| `phpList_phplist3` | WSL Debian `~/漏挖复审/phplist3` 的 Git origin 为 `https://github.com/phpList/phplist3.git`，README 引用一致。 |

WSL 复审资料来自 Debian 的 `~/漏挖复审`，原项目文件保持原样。UNA 报告包内的 `poc_una_rce_fullchain.py`、`una_rce_poc.py` 与目录中的同名副本按哈希去重；`unacms_UNA/exp/` 仅保留上述两个文件，未验证可运行性。调试、安装、会话生成脚本和运行数据未纳入归档。
