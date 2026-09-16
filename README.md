# All_Stars

All_Stars 是面向 **Web 相关开源项目**的漏洞研究与验证仓库，集中整理漏洞分析、独立复核、动态验证记录及 PoC / EXP，记录从候选发现到验证结论的研究过程。

项目使用**基于 Codex 的自研多 Agent 编排漏洞挖掘工具**开展分析与复核，并在本地或测试环境中部署目标项目，核验漏洞的触发条件、利用路径和实际影响。

## 研究范围与目标筛选

- **项目类型**：根据 GitHub 项目描述、README 和 Topics，筛选 Web Server、Web 应用、CMS、Web 框架及插件、API 服务等 Web 相关项目。
- **关注度要求**：以筛选时 GitHub Stars 不少于 **1,000**、具有一定社区影响力作为候选条件，结合实际使用场景和维护情况确定研究优先级。
- **分析范围**：围绕浏览器或 HTTP/HTTPS 可触达的功能，关注认证与权限控制、输入处理、文件操作、模板渲染、反序列化和服务端请求等安全问题。
- **目标记录**：保存原 GitHub 项目链接、筛选日期与 Stars 数、测试版本或 commit，以及运行依赖和必要配置。

以上标准用于候选目标筛选；具体研究进度、适用条件和验证结果以各项目报告为准。

## 挖掘与验证流程

通过多 Agent 协作组织线索挖掘、候选验证与独立复核，再结合目标环境中的动态证据形成结论。

1. **准备目标**  
   获取源码并固定测试版本或 commit，梳理项目功能、运行依赖、配置和待分析入口。

2. **挖掘线索**  
   分析攻击面与认证链路，追踪外部输入到敏感操作的数据流，记录候选漏洞的代码位置、触发条件和潜在影响。

3. **独立复核**  
   核对输入可控性、调用路径可达性、认证与权限前提，以及现有防护对结论的影响，保留复核依据和待验证问题。

4. **部署验证**  
   部署对应版本及必要依赖，通过实际 HTTP 请求或浏览器操作复现。记录请求与响应、日志或截图，对照预期影响与实际结果，并说明非默认配置、示例程序等额外条件。

5. **整理归档**  
   将分析报告、复核结论、部署步骤和动态证据存入 `reports/`，将独立 PoC / EXP 存入 `exp/`。未复现、环境受阻或已排除的候选同样记录原因。

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `仓库所有者_仓库名/reports/` | 漏洞报告、复核材料、部署验证记录及 PoC / EXP 说明。 |
| `仓库所有者_仓库名/exp/` | 独立 PoC / EXP 文件。 |
| [manifest.json](manifest.json) | 归档文件的路径、原始来源、大小与 SHA-256。 |

## 已归档项目

归档目录采用 `仓库所有者_仓库名` 命名，对应的原 GitHub 项目如下。当前共归档 **7 个项目、14 份报告或复核文件、10 个独立 PoC / EXP 文件**。文件数量用于说明归档规模，不代表独立漏洞数量。

| 归档目录 | 原 GitHub 项目 | 报告 / 复核文件数 | PoC / EXP 文件数 |
| --- | --- | ---: | ---: |
| [aFarkas_webshim](aFarkas_webshim/) | [aFarkas/webshim](https://github.com/aFarkas/webshim) | 2 | 3 |
| [CSAILVision_LabelMeAnnotationTool](CSAILVision_LabelMeAnnotationTool/) | [CSAILVision/LabelMeAnnotationTool](https://github.com/CSAILVision/LabelMeAnnotationTool) | 4 | 1 |
| [fossasia_fossasia11-drupal](fossasia_fossasia11-drupal/) | [fossasia/fossasia11-legacy](https://github.com/fossasia/fossasia11-legacy) | 2 | 1 |
| [zelon88_HRConvert2](zelon88_HRConvert2/) | [zelon88/HRConvert2](https://github.com/zelon88/HRConvert2) | 3 | 1 |
| [kubesphere_kubeeye](kubesphere_kubeeye/) | [kubesphere/kubeeye](https://github.com/kubesphere/kubeeye) | 1 | 1 |
| [unacms_UNA](unacms_UNA/) | [unacms/UNA](https://github.com/unacms/UNA) | 1 | 2 |
| [phpList_phplist3](phpList_phplist3/) | [phpList/phplist3](https://github.com/phpList/phplist3) | 1 | 1 |

`fossasia11-drupal` 上游现名为 `fossasia11-legacy`，归档目录沿用历史名称。目录中的仓库所有者用于标识项目来源，不代表报告作者。

## 验证记录要求

每项候选漏洞的报告应覆盖以下信息：

| 项目 | 记录内容 |
| --- | --- |
| 目标信息 | 项目来源、测试版本或 commit、相关文件与代码位置。 |
| 触发前提 | 认证状态、账号权限、配置、依赖和输入条件。 |
| 分析与复核 | 漏洞根因、关键数据流、复核依据及未解决的问题。 |
| 动态证据 | 运行环境、部署与复现步骤、预期结果、实际结果及日志。 |
| 最终状态 | 待部署验证、已部署验证、环境受阻、未复现或已排除，并说明判定依据。 |

分析复核与动态验证分别记录。“已部署验证”应有对应版本、实际运行环境和可复现证据支持；已有材料的状态以各报告中的记录为准。

## 归档与溯源

- 归档保留原始文件内容；同一项目、同一类别下，文件名与 SHA-256 均相同的副本合并，全部来源保留在 `manifest.json` 中。
- 来源清单记录归档路径、原始来源、文件大小和 SHA-256，便于追溯与完整性核对。
- 仓库集中保存报告与复现材料，完整项目源码可通过上表中的原 GitHub 项目获取。
- 历史归档过程未运行或修改 PoC / EXP，也未重新验证漏洞。报告中的原始相对路径予以保留，必要时结合来源清单定位。
