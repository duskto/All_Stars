# All_Stars

本目录归档原工作目录内各项目筛选保留的报告和 EXP 文件。目录统一按“仓库所有者_仓库名”命名，已核对项目内的 README 和原始项目路径记录；仓库所有者不代表漏洞报告作者。

| 作者_项目名 | 报告文件数 | EXP 文件数 |
| --- | ---: | ---: |
| [aFarkas_webshim](aFarkas_webshim/) | 2 | 3 |
| [CSAILVision_LabelMeAnnotationTool](CSAILVision_LabelMeAnnotationTool/) | 4 | 1 |
| [fossasia_fossasia11-drupal](fossasia_fossasia11-drupal/) | 2 | 1 |
| [zelon88_HRConvert2](zelon88_HRConvert2/) | 3 | 1 |

- 每个项目下 reports/ 保存报告、复核材料和 EXP 说明；exp/ 保存已有的独立 EXP 文件。
- 文件按原始字节复制；同项目、同类别、同名且 SHA-256 相同的副本合并，所有来源记入 manifest.json。
- manifest.json 记录归档路径、原始来源、大小和 SHA-256；压缩包来源以 压缩包路径::内部路径 表示，来源路径相对于原工作目录。
- 原项目目录和压缩包保持原样；未复制完整项目源码、运行状态文件、缓存或开发过程计划。
- 归档过程未运行或修改 EXP，未验证漏洞；报告中的原始相对路径保留，可能需要结合来源清单查找。

目录名称核对依据（路径相对于原工作目录）：

| 归档目录 | 项目内依据 |
| --- | --- |
| `aFarkas_webshim` | `aFarkas_webshim/webshim.zip::171_aFarkas_webshim/readme.md` 的下载地址为 `github.com/aFarkas/webshim/releases/latest`。 |
| `CSAILVision_LabelMeAnnotationTool` | `CSAILVision_LabelMeAnnotationTool/102_CSAILVision_LabelMeAnnotationTool/102_CSAILVision_LabelMeAnnotationTool/README.md` 的克隆地址为 `github.com/CSAILVision/LabelMeAnnotationTool.git`。 |
| `fossasia_fossasia11-drupal` | `fossasia11-drupal/fossasia11_drupal/README.md` 标题为 `fossasia11-drupal`；同目录 `context_snapshot.json` 的 `target_dir` 为 `D:\破壳项目\157_fossasia_fossasia11-drupal`，据此确认所有者标识为 `fossasia`。 |
| `zelon88_HRConvert2` | `zelon88_HRConvert2/112_zelon88_HRConvert2/112_zelon88_HRConvert2/README.md` 的安装文档地址位于 `github.com/zelon88/HRConvert2`。 |
