---
name: tangtao-java-code-repair
description: Use when you have a java-code-spec-scanner report and want to automatically repair the code issues and commit to a Git branch for review.
---

# Java Code Repair

## Overview

自动修复Java代码规范问题并提交到Git分支的工具。该工具与 `java-code-spec-scanner` 配合使用，根据扫描报告自动修复常见的代码规范问题，并将修复后的代码提交到专门的Git分支供开发人员审阅。

## When to Use

使用此工具：
- 当运行了 `java-code-spec-scanner` 并生成了扫描报告后
- 当需要自动修复代码规范问题时
- 当需要将修复的代码提交到专门的Git分支进行审阅时

## Features

### 自动修复
支持以下规则的自动修复：

- **G.EXP.05** - 添加null检查
- **G.PRM.07** - 使用try-with-resources
- **G.LOG.06** - 移除日志中的敏感信息
- **G.EDV.01** - 使用PreparedStatement
- **G.EDV.03** - 验证命令参数
- **G.TYP.02** - 添加除零检查
- **G.OTH.03** - 移除硬编码地址
- **G.CON.14** - 清理ThreadLocal

### Git集成
- 自动创建 `ai-repair-<timestamp>` 格式的分支
- 生成标准化的提交信息
- 推送到远程仓库
- 提供修复摘要

### 其他功能
- 预览模式：只显示修复建议，不实际修改文件
- 配置支持：自定义分支前缀、远程名称等
- 详细的错误处理和重试机制

## Quick Start

### 基本用法

```bash
# 首先使用扫描器生成报告
/tangtao-skills:java-code-spec-scanner

# 然后使用修复工具
cd ~/tangtao-skills/java-code-repair
python repair.py --report /path/to/report.md
```

### 预览模式

```bash
python repair.py --report /path/to/report.md --preview
```

### 指定Git远程

```bash
python repair.py --report /path/to/report.md --remote origin
```

### 配置文件

创建 `repair-config.json` 来自定义行为：

```json
{
  "branch_prefix": "ai-repair",
  "git_remote": "origin",
  "commit_prefix": "fix: ",
  "auto_push": true,
  "preview": false
}
```

## 修复规则说明

### G.EXP.05 - 添加null检查

**问题：** 直接使用可能为null的对象

**修复：**
```java
// 修复前
System.out.println(user.getName());

// 修复后
if (user != null) {
    System.out.println(user.getName());
}
```

### G.PRM.07 - 使用try-with-resources

**问题：** 资源未正确关闭

**修复：**
```java
// 修复前
FileInputStream fis = new FileInputStream("file.txt");
// 使用fis
fis.close();

// 修复后
try (FileInputStream fis = new FileInputStream("file.txt")) {
    // 使用fis
}
```

### G.LOG.06 - 移除敏感信息

**问题：** 日志中包含密码等敏感信息

**修复：**
```java
// 修复前
logger.info("Password: " + password);

// 修复后
logger.info("User login attempt");
```

## Git Branch Workflow

1. **创建分支**：基于当前分支创建 `ai-repair-202603271430`
2. **修复代码**：应用所有修复规则
3. **提交更改**：使用标准提交信息
4. **推送分支**：推送到远程仓库
5. **生成摘要**：显示修复摘要和分支URL

## 安全考虑

- 所有修复都经过测试验证
- 预览模式可以查看建议
- 修复只针对明确的规范问题
- 不会改变代码的业务逻辑
