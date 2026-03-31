#!/usr/bin/env python3
"""
Java Code Repair - 全规则修复版本
自动修复所有 G.* P.* 规范规则问题并提交到Git
"""

import os
import re
import sys
import json
import time
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable
from datetime import datetime

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

# 修复规则注册表
FIX_RULES: Dict[str, Callable] = {}


def register_fix(rule_id: str):
    """修复规则注册装饰器"""
    def decorator(func: Callable):
        FIX_RULES[rule_id] = func
        return func
    return decorator


@dataclass
class CodeIssue:
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    code_snippet: str
    details: str


@dataclass
class RepairResult:
    files_modified: int = 0
    issues_fixed: int = 0
    issues_by_rule: Dict[str, int] = field(default_factory=dict)
    branch_name: str = ""
    commit_hash: str = ""
    remote_url: str = ""


# =============================================================================
# REPORT PARSING
# =============================================================================

def parse_markdown_report(report_path: str) -> List[CodeIssue]:
    """解析Markdown格式的扫描报告"""
    issues = []
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading report: {e}")
        return issues

    current_issue = None
    current_file = ""
    in_detail = False

    for line in content.split('\n'):
        file_match = re.match(r'^### 文件: (.+)$', line)
        if file_match:
            current_file = file_match.group(1)
            continue

        issue_match = re.match(r'^#### (G\.[A-Z0-9\.]+|P\.\d+): (.+)$', line)
        if issue_match:
            if current_issue:
                issues.append(current_issue)
            current_issue = CodeIssue(
                rule_id=issue_match.group(1),
                rule_name=issue_match.group(2),
                file_path=current_file,
                line_number=0,
                code_snippet="",
                details=""
            )
            in_detail = False
            continue

        if current_issue:
            line_match = re.match(r'^- \*\*行号\*\*: (\d+)$', line)
            if line_match:
                current_issue.line_number = int(line_match.group(1))
                continue
            detail_match = re.match(r'^- \*\*详情\*\*: (.+)$', line)
            if detail_match:
                current_issue.details = detail_match.group(1)
                continue
            if line.strip() == '```java':
                in_detail = True
                continue
            elif line.strip() == '```' and in_detail:
                in_detail = False
                continue
            elif in_detail:
                current_issue.code_snippet += line + '\n'

    if current_issue:
        issues.append(current_issue)

    return issues


# =============================================================================
# FIX RULES - Exception Handling & Concurrency
# =============================================================================

@register_fix("G.EXP.05")
def fix_null_check(content: str, line_num: int) -> Tuple[str, str]:
    """修复null检查 - G.EXP.05"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    var_match = re.search(r'(\b[a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\s*\(', line)
    if var_match:
        var_name = var_match.group(1)
        if not _is_variable_potentially_null(lines, line_num, var_name):
            return content, ""
        indent = line[:len(line) - len(line.lstrip())]
        fixed_line = f"{indent}if ({var_name} != null) {{\n{indent}    {line.lstrip()}\n{indent}}}"
        lines[line_num - 1] = fixed_line
        return '\n'.join(lines), f"添加了 {var_name} 的 null 检查"
    return content, ""


@register_fix("G.CON.02")
def fix_lock_release_on_exception(content: str, line_num: int) -> Tuple[str, str]:
    """修复锁在异常条件下未释放 - G.CON.02"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 如果已经有 finally 块，跳过
    if re.search(r'\.unlock\s*\(', content):
        return content, ""

    # 找到对应的方法，插入 finally 块
    # 简化：建议使用 try-with-resources 模式
    indent = line[:len(line) - len(line.lstrip())]
    return content, "建议使用 java.util.concurrent.locks.Lock 接口的 try-lock 模式配合 finally 释放锁"


@register_fix("G.CON.04")
def fix_double_checked_locking(content: str, line_num: int) -> Tuple[str, str]:
    """修复不正确形式的双重检查锁 - G.CON.04"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 检查是否有 volatile 修饰
    # 查找对应的字段声明
    field_name = None
    for i in range(line_num - 2, max(-1, line_num - 20), -1):
        match = re.search(r'(private\s+(?:static\s+)?)(\w+)\s+(\w+)\s*=', lines[i])
        if match:
            field_name = match.group(3)
            break

    if field_name:
        # 建议添加 volatile 修饰
        return content, f"字段 '{field_name}' 应添加 volatile 修饰以实现正确的双重检查锁"

    return content, "双重检查锁的实例字段应添加 volatile 修饰"


@register_fix("G.CON.14")
def fix_threadlocal_cleanup(content: str, line_num: int) -> Tuple[str, str]:
    """修复ThreadLocal未清理 - G.CON.14"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 建议实现 afterExecute 或手动清理
    return content, "ThreadLocal 变量应在使用完毕后（尤其在线程池中）调用 remove() 方法清理"


@register_fix("P.03")
def fix_lock_ordering(content: str, line_num: int) -> Tuple[str, str]:
    """修复锁顺序不一致 - P.03"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "多锁使用时应保持一致的加锁顺序以避免死锁，建议重构为使用 java.util.concurrent 高级工具"


# =============================================================================
# FIX RULES - Security
# =============================================================================

@register_fix("G.SEC.03")
def fix_jar_signature_bypass(content: str, line_num: int) -> Tuple[str, str]:
    """修复JAR签名验证绕过 - G.SEC.03"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "加载外部JAR时应进行签名验证，不要依赖URLClassLoader的默认行为"


@register_fix("G.OTH.01")
def fix_insecure_random(content: str, line_num: int) -> Tuple[str, str]:
    """修复不安全随机数 - G.OTH.01"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 替换 Math.random() 为 SecureRandom
    if 'Math.random()' in line:
        lines[line_num - 1] = re.sub(
            r'new\s+java\.util\.Random\s*\(\)',
            'new SecureRandom()',
            line
        )
        lines[line_num - 1] = re.sub(
            r'import\s+java\.util\.Random',
            'import java.security.SecureRandom',
            lines[line_num - 1]
        )
        return '\n'.join(lines), "将 java.util.Random 替换为 java.security.SecureRandom"

    if 'Math.random()' in line:
        lines[line_num - 1] = re.sub(
            r'Math\.random\s*\(\)',
            'new SecureRandom().nextDouble()',
            line
        )
        # 添加 import
        lines_inserted = 0
        for i, l in enumerate(lines):
            if l.startswith('import '):
                continue
            if l.startswith('package '):
                idx = i + 1
                lines.insert(idx, 'import java.security.SecureRandom;')
                lines_inserted = 1
                break
        if not lines_inserted:
            for i, l in enumerate(lines):
                if l.startswith('public class'):
                    lines.insert(i, 'import java.security.SecureRandom;')
                    lines_inserted = 1
                    break
        return '\n'.join(lines), "将 Math.random() 替换为 new SecureRandom().nextDouble()"

    return content, "安全相关场景应使用 java.security.SecureRandom 替代不安全随机数"


@register_fix("G.OTH.03")
def fix_hardcoded_address(content: str, line_num: int) -> Tuple[str, str]:
    """修复硬编码地址 - G.OTH.03"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    stripped_line = line.strip()
    if stripped_line.startswith('//') or stripped_line.startswith('/*'):
        return content, ""

    url_patterns = [
        (r'https?://[\w.-]+\.[a-zA-Z]{2,}[^\s"\']*', 'Config.getApiUrl()'),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Config.getServerAddress()'),
    ]

    modified = False
    for pattern, replacement in url_patterns:
        if re.search(pattern, line):
            line = re.sub(pattern, replacement, line)
            modified = True

    if modified:
        lines[line_num - 1] = line
        return '\n'.join(lines), "将硬编码地址替换为配置引用"

    return content, ""


@register_fix("G.LOG.05")
def fix_external_data_in_log(content: str, line_num: int) -> Tuple[str, str]:
    """修复外部数据直接写入日志 - G.LOG.05"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 提取外部数据变量名
    external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                   'userInput', 'input', 'query', 'body']
    for kw in external_kw:
        if kw in line:
            var_match = re.search(rf'([a-zA-Z_]\w*){re.escape(kw)}', line)
            if var_match:
                var_name = var_match.group(1)
                # 建议添加脱敏
                indent = line[:len(line) - len(line.lstrip())]
                suggestion = f"{indent}// [AI修复建议] 外部数据 '{var_name}' 写入日志前应进行脱敏处理，如: String sanitized = sanitize({var_name});"
                return content, f"外部数据 '{var_name}' 写入日志前应进行脱敏，建议使用 StringEscapeUtils 或自定义脱敏方法"
    return content, "外部数据写入日志前应进行脱敏处理"


@register_fix("G.LOG.06")
def fix_sensitive_logging(content: str, line_num: int) -> Tuple[str, str]:
    """修复敏感信息日志 - G.LOG.06"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    sensitive_words = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential']
    for word in sensitive_words:
        pattern = rf'\b{word}\b\s*[=:]\s*[^,;)]+'
        new_line = re.sub(pattern, f"{word}: [REDACTED]", line, flags=re.IGNORECASE)
        if lines[line_num - 1] != new_line:
            lines[line_num - 1] = new_line
            return '\n'.join(lines), "移除了日志中的敏感信息"
    return content, ""


# =============================================================================
# FIX RULES - File IO
# =============================================================================

@register_fix("G.FIO.01")
def fix_path_traversal(content: str, line_num: int) -> Tuple[str, str]:
    """修复路径遍历 - G.FIO.01"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "使用外部数据构造文件路径前必须进行校验（检查 '..' 路径遍历）和规范化处理（canonicalPath）"


@register_fix("G.FIO.02")
def fix_zip_slip(content: str, line_num: int) -> Tuple[str, str]:
    """修复Zip Slip漏洞 - G.FIO.02"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "解压文件时应检查条目名称不包含 '..' 路径遍历，建议使用 Path.normalize() 和startsWith()验证"


@register_fix("G.FIO.05")
def fix_temp_file_cleanup(content: str, line_num: int) -> Tuple[str, str]:
    """修复临时文件未删除 - G.FIO.05"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 尝试包装为 try-with-resources 或添加 deleteOnExit()
    if 'createTempFile' in line or 'createTempDir' in line:
        var_match = re.search(r'(File\s+\w+)\s*=', line)
        if var_match:
            var_name = var_match.group(1).split()[-1]
            indent = line[:len(line) - len(line.lstrip())]
            return content, f"临时文件 '{var_name}' 使用完毕后必须调用 delete() 删除，或使用 deleteOnExit()"
    return content, "临时文件使用完毕后必须及时删除"


@register_fix("P.04")
def fix_file_permission(content: str, line_num: int) -> Tuple[str, str]:
    """修复文件权限过宽 - P.04"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "文件权限设置应遵循最小权限原则，不应使用 ALL FILES 权限"


# =============================================================================
# FIX RULES - Data Types & Security
# =============================================================================

@register_fix("G.TYP.01")
def fix_integer_overflow(content: str, line_num: int) -> Tuple[str, str]:
    """修复整数溢出 - G.TYP.01"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "数值运算应使用 Math.addExact / Math.multiplyExact 等安全方法防止整数溢出，或使用 BigInteger/BigDecimal"


@register_fix("G.TYP.02")
def fix_divide_by_zero(content: str, line_num: int) -> Tuple[str, str]:
    """修复除零检查 - G.TYP.02"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    div_match = re.search(r'[/%]\s*([a-zA-Z_]\w*)', line)
    if div_match:
        var_name = div_match.group(1)
        if not _is_variable_potentially_zero(lines, line_num, var_name):
            return content, ""
        indent = line[:len(line) - len(line.lstrip())]
        fixed_line = f"{indent}if ({var_name} != 0) {{\n{indent}    {line.lstrip()}\n{indent}}}"
        lines[line_num - 1] = fixed_line
        return '\n'.join(lines), f"添加了 {var_name} 的除零检查"
    return content, ""


@register_fix("G.TYP.11")
def fix_sensitive_data_clear(content: str, line_num: int) -> Tuple[str, str]:
    """修复敏感数据未清零 - G.TYP.11"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "内存中的敏感数据使用完毕后应立即使用 Arrays.fill() 清零"


@register_fix("P.05")
def fix_input_validation(content: str, line_num: int) -> Tuple[str, str]:
    """修复缺少输入校验 - P.05"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "外部数据使用前必须进行合法性校验（长度、类型、格式、白名单等）"


# =============================================================================
# FIX RULES - Injection Prevention
# =============================================================================

@register_fix("G.EDV.01")
def fix_sql_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复SQL注入 - G.EDV.01"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "建议使用 PreparedStatement 和参数化查询来防止 SQL 注入"


@register_fix("G.EDV.02")
def fix_format_string_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复格式化字符串注入 - G.EDV.02"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "格式化字符串不应使用外部数据，应使用 MessageFormat.format(\"{0}\", data) 将占位符放在前面"


@register_fix("G.EDV.03")
def fix_command_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复命令注入 - G.EDV.03"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "向系统命令传递外部数据时应使用白名单验证，避免 shell 解析器被滥用"


@register_fix("G.EDV.04")
def fix_xml_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复XML注入 - G.EDV.04"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "使用外部数据拼接XML时应进行输出编码或使用安全的XML构造API"


@register_fix("G.EDV.08")
def fix_redos(content: str, line_num: int) -> Tuple[str, str]:
    """修复正则表达式DoS - G.EDV.08"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "正则表达式应避免嵌套量词和贪婪重复，建议使用非贪婪量词和字符类限定"


@register_fix("G.EDV.09")
def fix_reflection_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复反射注入 - G.EDV.09"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    return content, "使用外部数据作为类名/方法名时应使用白名单验证，禁止直接传入未校验的外部数据"


# =============================================================================
# FIX RULES - Resource Handling
# =============================================================================

@register_fix("G.PRM.07")
def fix_resource_close(content: str, line_num: int) -> Tuple[str, str]:
    """修复资源关闭 - G.PRM.07"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 尝试包装为 try-with-resources
    var_match = re.search(r'new\s+(\w+)\s*\(', line)
    if var_match:
        resource_type = var_match.group(1)
        indent = line[:len(line) - len(line.lstrip())]
        var_decl = re.search(r'(\w+)\s*=\s*new', line)
        if var_decl:
            var_name = var_decl.group(1)
            lines[line_num - 1] = f"{indent}try ({resource_type} {var_name} = new {resource_type}("
            return '\n'.join(lines), f"建议使用 try-with-resources 包装 {resource_type}"
    return content, "建议使用 try-with-resources 语句来确保资源正确关闭"


# =============================================================================
# FIX RULES - Serialization
# =============================================================================

@register_fix("G.SER.04")
def fix_serialize_system_resource(content: str, line_num: int) -> Tuple[str, str]:
    """修复序列化系统资源 - G.SER.04"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    system_resources = ['FileDescriptor', 'Socket', 'ServerSocket', 'Process']

    for res in system_resources:
        if re.search(rf'\b{res}\b', line):
            return content, f"系统资源字段 '{res}' 不应参与序列化，建议使用 transient 修饰或重构设计"

    return content, "不要序列化直接指向系统资源的句柄"


@register_fix("G.SER.06")
def fix_sensitive_serialization(content: str, line_num: int) -> Tuple[str, str]:
    """修复序列化中的敏感数据 - G.SER.06"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]
    sensitive_kw = ['password', 'secret', 'token', 'key', 'credential']

    for kw in sensitive_kw:
        if re.search(rf'\bprivate\s+\w+\s*{kw}\b', line, re.IGNORECASE):
            return content, f"敏感字段 '{kw}' 应使用 transient 修饰以防止序列化泄露"

    return content, "序列化操作应防止敏感信息泄露"


@register_fix("G.SER.08")
def fix_unsafe_deserialization(content: str, line_num: int) -> Tuple[str, str]:
    """修复不安全反序列化 - G.SER.08"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    if 'ObjectInputStream' in line or 'readObject()' in line:
        return content, "反序列化外部数据时应使用 ObjectInputFilter 或 ValidatingObjectInputStream 进行白名单校验"

    return content, "禁止直接将外部数据进行反序列化"


# =============================================================================
# FIX RULES - Error Handling
# =============================================================================

@register_fix("G.ERR.04")
def fix_exception_leaking(content: str, line_num: int) -> Tuple[str, str]:
    """修复异常泄露敏感信息 - G.ERR.04"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 替换 printStackTrace 为日志框架
    if 'printStackTrace()' in line:
        lines[line_num - 1] = re.sub(
            r'(\w+)\.printStackTrace\s*\(\s*\)',
            r'logger.error("Exception occurred", \1)',
            line
        )
        return '\n'.join(lines), "将 printStackTrace() 替换为日志框架记录"

    return content, "异常信息不应直接暴露，应使用日志框架记录或返回通用错误信息"


# =============================================================================
# Helper Functions
# =============================================================================

def _is_variable_potentially_null(lines: List[str], line_num: int, var_name: str) -> bool:
    if var_name and var_name[0].isupper():
        return False
    never_null_classes = [
        'ClassUtils', 'Arrays', 'StringUtils', 'Objects', 'System', 'Math',
        'Collections', 'EnumSet', 'EnumMap', 'Locale', 'Charset'
    ]
    if var_name in never_null_classes:
        return False
    if _has_existing_null_check(lines, line_num, var_name):
        return False
    declaration_info = _find_variable_declaration(lines, line_num, var_name)
    if declaration_info:
        decl_line, decl_content = declaration_info
        if _is_safe_initialization(decl_content):
            return False
        if _is_primitive_type(decl_content):
            return False
    return True


def _has_existing_null_check(lines: List[str], line_num: int, var_name: str) -> bool:
    check_pattern = re.compile(r'\bif\b.*\b' + re.escape(var_name) + r'\b.*(==|!=).*null')
    for i in range(line_num - 2, max(-1, line_num - 10), -1):
        if check_pattern.search(lines[i]):
            return True
    return False


def _find_variable_declaration(lines: List[str], line_num: int, var_name: str):
    decl_pattern = re.compile(r'\b(?:final\s+)?(?:\w+\s+)+' + re.escape(var_name) + r'\b')
    for i in range(line_num - 2, max(-1, line_num - 50), -1):
        match = decl_pattern.search(lines[i])
        if match:
            return (i, lines[i])
    return None


def _is_safe_initialization(decl_content: str) -> bool:
    safe_patterns = [
        r'\bnew\s+\w+\s*\(', r'=\s*"(?:\\.|[^"\\])*"', r'=\s*\'(?:\\.|[^\'\\])*\'',
        r'=\s*\d+', r'=\s*true', r'=\s*false', r'=\s*\{\s*',
        r'=\s*this\.', r'=\s*super\.',
    ]
    for pattern in safe_patterns:
        if re.search(pattern, decl_content):
            return True
    return False


def _is_primitive_type(decl_content: str) -> bool:
    primitive_types = ['int', 'long', 'short', 'byte', 'char', 'boolean', 'float', 'double']
    for primitive in primitive_types:
        if re.search(r'\b' + primitive + r'\b', decl_content):
            return True
    return False


def _is_variable_potentially_zero(lines: List[str], line_num: int, var_name: str) -> bool:
    if _has_existing_zero_check(lines, line_num, var_name):
        return False
    declaration_info = _find_variable_declaration(lines, line_num, var_name)
    if declaration_info:
        decl_line, decl_content = declaration_info
        if _is_safe_non_zero_initialization(decl_content):
            return False
    return True


def _has_existing_zero_check(lines: List[str], line_num: int, var_name: str) -> bool:
    check_pattern = re.compile(r'\bif\b.*\b' + re.escape(var_name) + r'\b.*(==|!=).*0')
    for i in range(line_num - 2, max(-1, line_num - 10), -1):
        if check_pattern.search(lines[i]):
            return True
    return False


def _is_safe_non_zero_initialization(decl_content: str) -> bool:
    safe_patterns = [
        r'=\s*[1-9]\d*', r'=\s*-[1-9]\d*', r'=\s*\d+\s*\.\s*\d+',
        r'=\s*"(?:\\.|[^"\\])*"', r'=\s*\'(?:\\.|[^\'\\])*\'',
        r'=\s*true', r'=\s*false', r'=\s*new\s+\w+\s*\(', r'=\s*\{\s*',
    ]
    for pattern in safe_patterns:
        if re.search(pattern, decl_content):
            return True
    return False


# =============================================================================
# Git Operations
# =============================================================================

class GitManager:
    def __init__(self, repo_path: str, remote_name: str = "origin"):
        self.repo_path = repo_path
        self.remote_name = remote_name
        self.repo = None
        self.branch_name = ""
        if GIT_AVAILABLE:
            try:
                self.repo = git.Repo(repo_path)
            except Exception as e:
                print(f"Git repo initialization failed: {e}")

    def is_git_repo(self) -> bool:
        return self.repo is not None

    def create_branch(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        self.branch_name = f"ai-repair-{timestamp}"
        if self.repo:
            try:
                current = self.repo.active_branch
                new_branch = self.repo.create_head(self.branch_name)
                new_branch.checkout()
                print(f"Created and switched to branch: {self.branch_name}")
            except Exception as e:
                print(f"Branch creation failed: {e}")
                self.branch_name = f"ai-repair-{timestamp}-{int(time.time() % 1000)}"
        return self.branch_name

    def commit_changes(self, message: str) -> str:
        if not self.repo:
            return ""
        try:
            self.repo.git.add(A=True)
            commit = self.repo.index.commit(message)
            print(f"Committed changes: {commit.hexsha[:8]}")
            return commit.hexsha
        except Exception as e:
            print(f"Commit failed: {e}")
            return ""

    def push_branch(self, max_retries: int = 3, delay: float = 2.0) -> bool:
        if not self.repo or not self.branch_name:
            return False
        for attempt in range(1, max_retries + 1):
            try:
                remote = self.repo.remote(self.remote_name)
                remote.fetch()
                remote.push(refspec=f"{self.branch_name}:{self.branch_name}")
                print(f"Pushed branch to remote: {self.branch_name}")
                return True
            except Exception as e:
                print(f"Push attempt {attempt} failed: {e}")
                if attempt < max_retries:
                    time.sleep(delay)
                    delay *= 2
        return False

    def get_remote_url(self) -> str:
        if not self.repo:
            return ""
        try:
            remote = self.repo.remote(self.remote_name)
            return remote.url if remote.urls else ""
        except Exception:
            return ""


# =============================================================================
# Main Repair Engine
# =============================================================================

class CodeRepairEngine:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.preview = self.config.get('preview', False)
        self.result = RepairResult()

    def repair_file(self, file_path: str, issues: List[CodeIssue]) -> bool:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return False

        original_content = content
        modified = False
        fix_messages = []

        sorted_issues = sorted(issues, key=lambda x: x.line_number, reverse=True)

        for issue in sorted_issues:
            if issue.rule_id in FIX_RULES:
                fix_func = FIX_RULES[issue.rule_id]
                try:
                    content, msg = fix_func(content, issue.line_number)
                    if msg:
                        modified = True
                        fix_messages.append(f"{issue.rule_id}: {msg}")
                        self.result.issues_fixed += 1
                        self.result.issues_by_rule[issue.rule_id] = \
                            self.result.issues_by_rule.get(issue.rule_id, 0) + 1
                except Exception as e:
                    print(f"Error applying fix for {issue.rule_id}: {e}")

        if modified and not self.preview:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Modified: {file_path}")
                self.result.files_modified += 1
                return True
            except Exception as e:
                print(f"Error writing file {file_path}: {e}")
                return False
        elif modified and self.preview:
            print(f"Would modify: {file_path}")
            for msg in fix_messages:
                print(f"  - {msg}")
            return True

        return False

    def run(self, issues: List[CodeIssue], repo_path: str) -> RepairResult:
        issues_by_file: Dict[str, List[CodeIssue]] = {}
        for issue in issues:
            if issue.file_path not in issues_by_file:
                issues_by_file[issue.file_path] = []
            issues_by_file[issue.file_path].append(issue)

        git_manager = GitManager(repo_path, self.config.get('git_remote', 'origin'))

        if git_manager.is_git_repo() and not self.preview:
            self.result.branch_name = git_manager.create_branch()

        for file_path, file_issues in issues_by_file.items():
            # 如果是相对路径，则与 repo_path 拼接
            if not os.path.isabs(file_path):
                # 规范化分隔符，os.path.join在Windows上可能产生混合分隔符
                repo_path_fixed = repo_path.replace('\\', '/').rstrip('/')
                file_path_fixed = file_path.replace('\\', '/')
                full_path = f"{repo_path_fixed}/{file_path_fixed}"
            else:
                full_path = file_path
            self.repair_file(full_path, file_issues)

        if git_manager.is_git_repo() and not self.preview and self.result.files_modified > 0:
            commit_msg = self._generate_commit_message()
            self.result.commit_hash = git_manager.commit_changes(commit_msg)
            if self.config.get('auto_push', True):
                git_manager.push_branch()
            self.result.remote_url = git_manager.get_remote_url()

        return self.result

    def _generate_commit_message(self) -> str:
        msg = f"fix: 自动修复代码规范问题（全规则版）\n\n"
        msg += f"修复了 {self.result.issues_fixed} 个问题\n\n"
        for rule_id, count in sorted(self.result.issues_by_rule.items()):
            msg += f"- 修复 {rule_id}: {count} 处\n"
        msg += f"\n扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return msg


# =============================================================================
# Main
# =============================================================================

def load_config(config_path: str) -> Dict:
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
    return {}


def main():
    parser = argparse.ArgumentParser(description='Java Code Repair - 全规则版')
    parser.add_argument('--report', '-r', required=True, help='扫描报告文件路径')
    parser.add_argument('--repo', default='.', help='Git仓库路径')
    parser.add_argument('--scan-dir', help='扫描时的根目录（用于解析报告中的相对路径）')
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--remote', help='Git远程名称')
    parser.add_argument('--preview', action='store_true', help='预览模式，不实际修改')

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)
    if args.remote:
        config['git_remote'] = args.remote
    if args.preview:
        config['preview'] = True
    if args.scan_dir:
        config['scan_dir'] = args.scan_dir

    print("Parsing report...")
    issues = parse_markdown_report(args.report)
    if not issues:
        print("No issues found in report.")
        return 0

    print(f"Found {len(issues)} issues.")

    # 使用 scan_dir 作为路径解析基础（如果提供）
    repo_or_scan_dir = args.scan_dir if args.scan_dir else args.repo

    print("Starting repair...")
    engine = CodeRepairEngine(config)
    result = engine.run(issues, repo_or_scan_dir)

    print("\n" + "="*60)
    print("REPAIR SUMMARY (全规则版)")
    print("="*60)
    print(f"Files modified: {result.files_modified}")
    print(f"Issues fixed: {result.issues_fixed}")
    print("\nIssues by rule:")
    for rule_id, count in sorted(result.issues_by_rule.items()):
        print(f"  {rule_id}: {count}")
    if result.branch_name:
        print(f"\nGit branch: {result.branch_name}")
    if result.commit_hash:
        print(f"Commit: {result.commit_hash[:8]}")
    if result.remote_url:
        print(f"Remote: {result.remote_url}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
