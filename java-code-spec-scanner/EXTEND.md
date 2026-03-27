# Java Code Specification Scanner Skill

## 使用方法

当您需要扫描Java项目的代码规范和安全问题时，请使用此skill。

### 功能特点

- 支持20+条业界公认的Java编码规范规则
- 检测空指针引用、SQL注入、资源泄漏等常见问题
- 生成详细的Markdown格式报告
- 支持自定义配置

### 快速开始

在Claude Code中激活此skill后，只需运行：

```bash
cd ~/.baoyu-skills/java-code-spec-scanner
python scanner.py <your-java-project-path>
```

### 报告输出

扫描结果会自动生成一个详细的Markdown报告，包含：
- 扫描摘要（文件数、问题数）
- 按规则统计的问题分布
- 详细的问题列表（文件位置、代码片段、修复建议）

### 配置文件

您可以在项目根目录创建 `java-scanner-config.json` 文件来自定义扫描行为：

```json
{
  "excludeDirs": ["target", "build"],
  "rules": {
    "G.EXP.05": true,
    "G.LOG.06": false
  }
}
```

### 注意事项

此工具使用静态分析技术，可能存在少量误报。建议结合专业工具和人工审核进行全面检测。
