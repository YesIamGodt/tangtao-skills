# Tangtao Java Skills

这是一个包含Java代码规范扫描和自动修复工具的技能集合。

## 技能列表

### 1. tangtao-java-code-spec-scanner
Java代码规范扫描器，用于扫描Java代码库以检查是否符合业界公认的编码和安全规范。

**功能特性：**
- 29条预定义规则（支持全量 G.* / P.* 规则）
- 涵盖空指针处理、安全性、IO操作、并发等多个方面
- 生成详细的Markdown格式报告

### 2. tangtao-java-code-repair
Java代码自动修复工具，根据扫描报告自动修复代码规范问题并提交到Git分支供开发人员审阅。

**功能特性：**
- 支持多种规则的自动修复
- 自动创建 `ai-repair-<timestamp>` 格式的Git分支
- 生成标准化的提交信息
- 推送到远程仓库

## 安装和使用

### 在 Claude Code 中使用

将两个技能文件夹复制到 `~/.claude/skills/` 目录下，然后可以通过以下命令调用：

```bash
# 扫描代码
/tangtao-java-code-spec-scanner

# 修复代码
/tangtao-java-code-repair
```

### 作为独立工具使用

```bash
cd tangtao-java-code-spec-scanner
python scanner.py

cd ../tangtao-java-code-repair
python repair.py --report /path/to/report.md
```

## 支持的规则

### Exception Handling & Concurrency
- **G.EXP.05**: 禁止直接使用可能为null的对象
- **G.CON.02**: 在异常条件下，保证释放已持有的锁
- **G.CON.04**: 避免使用不正确形式的双重检查锁
- **G.CON.14**: 线程池中的线程结束后必须清理自定义的ThreadLocal变量
- **P.03**: 使用相同的顺序请求和释放锁来避免死锁

### Security
- **G.SEC.03**: 加载外部JAR文件时，不要依赖默认自动签名检查
- **G.OTH.01**: 安全场景下必须使用密码学意义上的安全随机数
- **G.OTH.03**: 禁止代码中包含公网地址
- **G.LOG.05**: 禁止直接使用外部数据记录日志
- **G.LOG.06**: 禁止在日志中记录口令、密钥等敏感信息

### File IO
- **G.FIO.01**: 使用外部数据构造的文件路径前必须进行校验
- **G.FIO.02**: 从ZipInputStream中解压文件必须进行安全检查
- **G.FIO.05**: 临时文件使用完毕必须及时删除
- **P.04**: 在多用户系统中创建文件时指定合适的访问许可

### Data Types & Security
- **G.TYP.01**: 进行数值运算时，避免整数溢出
- **G.TYP.02**: 确保除法运算和模运算中的除数不为0
- **G.TYP.11**: 内存中的敏感信息使用完毕后应立即清0
- **P.05**: 外部数据使用前必须进行合法性校验

### Injection Prevention
- **G.EDV.01**: 禁止直接使用外部数据来拼接SQL语句
- **G.EDV.02**: 禁止使用外部数据构造格式化字符串
- **G.EDV.03**: 禁止向Runtime.exec()方法或ProcessBuilder类传递外部数据
- **G.EDV.04**: 禁止直接使用外部数据来拼接XML
- **G.EDV.08**: 正则表达式应该尽量简单，防止ReDoS攻击
- **G.EDV.09**: 禁止直接使用外部数据作为反射操作中的类名/方法名

### Resource Handling
- **G.PRM.07**: 进行IO类操作时，必须在try-with-resource或finally里关闭资源

### Serialization
- **G.SER.04**: 不要序列化直接指向系统资源的句柄
- **G.SER.06**: 序列化操作要防止敏感信息泄露
- **G.SER.08**: 禁止直接将外部数据进行反序列化

### Error Handling
- **G.ERR.04**: 防止通过异常泄露敏感信息

## 许可证

本项目仅供学习和参考使用。
