# Java Code Specification Scanner

## 简介

Java代码规范扫描器是一个轻量级但功能强大的静态代码分析工具，用于检查Java代码的安全性、质量和合规性。它基于业界公认的编码规范，检测常见的安全漏洞和代码质量问题。

## 安装

### 依赖

- Python 3.6 或更高版本
- 推荐使用虚拟环境

### 安装步骤

```bash
# 克隆或下载skill到本地
cd ~/.baoyu-skills/java-code-spec-scanner

# 安装依赖（可选，但建议安装）
pip install -r requirements.txt
```

## 使用方法

### 基本使用

在终端中运行以下命令：

```bash
cd ~/.baoyu-skills/java-code-spec-scanner
python scanner.py <target-path>
```

其中 `<target-path>` 可以是：
- 单个Java文件路径
- 包含Java文件的目录路径（会递归扫描）

### 输出格式

默认会在控制台输出Markdown格式的报告。你也可以使用 `-o` 选项将报告保存到文件：

```bash
python scanner.py <target-path> -o report.md
```

### 配置文件

你可以在项目根目录创建 `java-scanner-config.json` 文件来自定义扫描行为：

```json
{
  "excludeDirs": ["target", "build", "test"],
  "excludePatterns": ["\\.class$"],
  "rules": {
    "G.EXP.05": true,
    "G.LOG.06": true,
    "G.EDV.01": false
  }
}
```

**配置项说明：**

- `excludeDirs`：要排除的目录列表
- `excludePatterns`：要排除的文件模式（正则表达式）
- `rules`：规则启用/禁用配置（true启用，false禁用）

## 规则说明

该扫描器实现了以下规则：

### 安全相关规则
- **G.LOG.06** - 禁止在日志中记录敏感信息（密码、密钥等）
- **G.EDV.01** - 禁止SQL语句拼接，防止SQL注入
- **G.EDV.03** - 禁止命令注入风险
- **G.SER.08** - 防止不安全的反序列化
- **G.ERR.04** - 防止通过异常泄露敏感信息
- **G.OTH.03** - 禁止硬编码公网地址

### 代码质量规则
- **G.EXP.05** - 防止空指针引用
- **G.CON.02** - 确保锁资源正确释放
- **G.CON.04** - 避免不正确的双重检查锁
- **G.CON.14** - ThreadLocal变量清理
- **G.PRM.07** - 资源正确关闭
- **G.FIO.02** - 安全的Zip文件解压
- **G.OTH.01** - 使用安全的随机数

## 报告格式

扫描报告包含以下部分：

1. **扫描摘要** - 扫描文件数、问题总数、按规则统计

2. **详细问题列表** - 按文件分组：
   - 规则ID和名称
   - 文件位置和行号
   - 问题详情
   - 代码片段（包含上下文）

## 在 Claude Code 中使用

1. 激活该skill

2. 在需要扫描的Java项目中，使用以下命令：
   ```bash
   /skill java-code-spec-scanner
   ```

3. 扫描结果将直接在Claude Code中显示

## 扩展规则

你可以通过在 `scanner.py` 文件中添加新的规则函数来扩展扫描功能。使用 `@register_rule` 装饰器：

```python
@register_rule("你的规则ID", "规则名称")
def check_your_rule(content: str, file_path: str) -> List[Issue]:
    issues = []
    # 你的检测逻辑
    return issues
```

## 注意事项

1. **误报问题**：该工具使用正则表达式为主的检测方法，可能会有少量误报
2. **覆盖范围**：该工具主要检测常见的安全和质量问题，但无法发现所有可能的问题
3. **专业性**：对于大型项目，建议结合专业工具（如SonarQube）进行全面检测

## 反馈和改进

如果发现问题或有改进建议，请提交issue或pull request。

## 许可证

MIT License
