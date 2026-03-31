#!/usr/bin/env python3
"""
Java Code Specification Scanner
A comprehensive Java code scanner for security and quality issues.
"""

import os
import re
import sys
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple, Set
from collections import defaultdict

# Constants
RULE_REGISTRY: Dict[str, Tuple[str, Callable]] = {}


@dataclass
class Issue:
    """Represents a single issue found in the code."""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    code_snippet: str
    details: str


@dataclass
class ScanResult:
    """Result of a complete scan."""
    files_scanned: int = 0
    total_issues: int = 0
    issues: List[Issue] = field(default_factory=list)
    rule_counts: Dict[str, int] = field(default_factory=dict)
    scanned_files: List[str] = field(default_factory=list)


def register_rule(rule_id: str, rule_name: str):
    """Decorator to register a rule function."""
    def decorator(func: Callable):
        RULE_REGISTRY[rule_id] = (rule_name, func)
        return func
    return decorator


def extract_code_snippet(lines: List[str], line_num: int, context: int = 3) -> str:
    """Extract a code snippet with context around the issue line."""
    start = max(0, line_num - context)
    end = min(len(lines), line_num + context + 1)
    snippet = []
    for i in range(start, end):
        prefix = f"> {i+1}: " if i == line_num else f"  {i+1}: "
        snippet.append(prefix + lines[i].rstrip())
    return "\n".join(snippet)


# ============================================================================
# VARIABLE ANALYSIS HELPERS
# ============================================================================

@dataclass
class VariableInfo:
    """Information about a variable's declaration and usage."""
    name: str
    line_number: int
    is_initialized: bool = False
    initial_value: Optional[str] = None
    is_final: bool = False
    has_nonnull_annotation: bool = False
    is_parameter: bool = False
    is_field: bool = False


def extract_variable_declarations(lines: List[str]) -> Dict[str, List[VariableInfo]]:
    """Extract variable declarations from the code."""
    variables: Dict[str, List[VariableInfo]] = defaultdict(list)

    field_pattern = re.compile(r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:@\w+\s+)*([a-zA-Z_]\w*)\s+([a-zA-Z_]\w*)\s*(?:=\s*([^;]+))?;')
    local_var_pattern = re.compile(r'(?:final\s+)?(?:@\w+\s+)*([a-zA-Z_]\w*)\s+([a-zA-Z_]\w*)\s*(?:=\s*([^;]+))?;')
    param_pattern = re.compile(r'(?:@\w+\s+)*([a-zA-Z_]\w*)\s+([a-zA-Z_]\w*)\s*(?:,|\))')

    for line_num, line in enumerate(lines):
        stripped_line = line.strip()

        # Skip comments
        if stripped_line.startswith('//') or stripped_line.startswith('/*'):
            continue

        # Check for field declarations
        field_match = field_pattern.search(line)
        if field_match:
            var_name = field_match.group(2)
            var_info = VariableInfo(
                name=var_name,
                line_number=line_num,
                is_initialized=field_match.group(3) is not None,
                initial_value=field_match.group(3).strip() if field_match.group(3) else None,
                is_final='final' in line,
                has_nonnull_annotation='@NonNull' in line or '@NotNull' in line,
                is_field=True
            )
            variables[var_name].append(var_info)
            continue

        # Check for local variable declarations
        local_match = local_var_pattern.search(line)
        if local_match and not any(keyword in line for keyword in ['if', 'for', 'while', 'switch', 'catch']):
            var_name = local_match.group(2)
            var_info = VariableInfo(
                name=var_name,
                line_number=line_num,
                is_initialized=local_match.group(3) is not None,
                initial_value=local_match.group(3).strip() if local_match.group(3) else None,
                is_final='final' in line,
                has_nonnull_annotation='@NonNull' in line or '@NotNull' in line
            )
            variables[var_name].append(var_info)

    return variables


def is_safe_initialization(initial_value: Optional[str]) -> bool:
    """Check if an initial value is safe (definitely not null)."""
    if not initial_value:
        return False

    # New object creation
    if initial_value.startswith('new '):
        return True

    # String literals
    if initial_value.startswith('"'):
        return True

    # Numeric literals
    if re.match(r'^[\d.]+', initial_value):
        return True

    # Boolean literals
    if initial_value in ['true', 'false']:
        return True

    # this/super
    if initial_value in ['this', 'super']:
        return True

    return False


def find_variable_in_scope(var_name: str, line_num: int, variables: Dict[str, List[VariableInfo]]) -> Optional[VariableInfo]:
    """Find the most relevant variable declaration in scope for a given line."""
    if var_name not in variables:
        return None

    # Find the last declaration before the usage line
    relevant_vars = [v for v in variables[var_name] if v.line_number < line_num]
    if not relevant_vars:
        # Check if there's a declaration at or after (might be a field)
        relevant_vars = variables[var_name]

    if not relevant_vars:
        return None

    # Return the closest one before the usage line, or the first one
    return sorted(relevant_vars, key=lambda v: abs(v.line_number - line_num))[0]


# ============================================================================
# RULES IMPLEMENTATION
# ============================================================================

@register_rule("G.EXP.05", "禁止直接使用可能为null的对象，防止出现空指针引用")
def check_null_pointer_dereference(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    # Extract variable declarations first
    variables = extract_variable_declarations(lines)

    # Pattern to find method calls on objects that might be null
    patterns = [
        (r'\b([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\s*\(', 1, 2),  # method call
    ]

    exclude_vars = ['this', 'super', 'class', 'true', 'false', 'null', 'java', 'javax', 'org', 'com', 'net']
    exclude_prefixes = ['java.', 'javax.', 'org.', 'com.', 'net.']

    for line_num, line in enumerate(lines):
        stripped_line = line.strip()

        # Skip comments, imports, package declarations, annotations
        if (stripped_line.startswith('//') or
            stripped_line.startswith('/*') or
            stripped_line.startswith('*') or
            stripped_line.startswith('import') or
            stripped_line.startswith('package') or
            stripped_line.startswith('@')):
            continue

        for pattern, var_group, method_group in patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                var_name = match.group(var_group)

                # Skip System.out/err
                if 'System.' + var_name in line:
                    continue

                # Skip if variable name is uppercase (constants)
                if var_name.isupper():
                    continue

                # Skip excluded variables
                if var_name in exclude_vars:
                    continue

                # Skip if starts with excluded prefixes
                if any(var_name.startswith(prefix) for prefix in exclude_prefixes):
                    continue

                # Skip if in a null check context
                null_check_patterns = [
                    rf'if\s*\(\s*{re.escape(var_name)}\s*!=\s*null',
                    rf'if\s*\(\s*null\s*!=\s*{re.escape(var_name)}',
                    rf'if\s*\(\s*{re.escape(var_name)}\s*==\s*null',
                    rf'if\s*\(\s*null\s*==\s*{re.escape(var_name)}',
                ]
                in_null_check = False
                for check in null_check_patterns:
                    if re.search(check, line):
                        in_null_check = True
                        break
                if in_null_check:
                    continue

                # Analyze variable declaration
                var_info = find_variable_in_scope(var_name, line_num, variables)

                # Skip if variable is final and initialized
                if var_info and var_info.is_final and var_info.is_initialized:
                    continue

                # Skip if variable has @NonNull annotation
                if var_info and var_info.has_nonnull_annotation:
                    continue

                # Skip if variable is safely initialized
                if var_info and var_info.is_initialized and is_safe_initialization(var_info.initial_value):
                    continue

                # Only flag if we can't confirm it's safe
                issues.append(Issue(
                    rule_id="G.EXP.05",
                    rule_name="禁止直接使用可能为null的对象，防止出现空指针引用",
                    file_path=file_path,
                    line_number=line_num + 1,
                    code_snippet=extract_code_snippet(lines, line_num),
                    details=f"变量 '{var_name}' 可能为null，建议添加null检查后再使用"
                ))
                break
    return issues


@register_rule("G.CON.02", "在异常条件下，保证释放已持有的锁")
def check_lock_release(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")
    # Pattern: lock() without finally block unlock()
    lock_pattern = re.compile(r'\.lock\(\)')
    unlock_pattern = re.compile(r'\.unlock\(\)')

    in_try_block = False
    has_finally = False
    lock_lines = []

    for i, line in enumerate(lines):
        if 'try' in line:
            in_try_block = True
        if 'finally' in line and in_try_block:
            has_finally = True
        if lock_pattern.search(line):
            lock_lines.append(i)
        # Check for end of block
        if '}' in line and in_try_block:
            if lock_lines and not has_finally:
                for lock_line in lock_lines:
                    issues.append(Issue(
                        rule_id="G.CON.02",
                        rule_name="在异常条件下，保证释放已持有的锁",
                        file_path=file_path,
                        line_number=lock_line + 1,
                        code_snippet=extract_code_snippet(lines, lock_line),
                        details="获取锁后建议在finally块中释放锁，以防止异常时资源泄漏"
                    ))
            in_try_block = False
            has_finally = False
            lock_lines = []
    return issues


@register_rule("G.CON.04", "避免使用不正确形式的双重检查锁")
def check_double_check_locking(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    # Look for double-check locking patterns
    if_content = ""
    nested_level = 0
    in_dcl = False
    dcl_start_line = 0

    for i, line in enumerate(lines):
        if 'synchronized' in line and nested_level > 0:
            in_dcl = True
            dcl_start_line = i - 2 if i >= 2 else 0
        if 'if' in line:
            nested_level += 1
        if '}' in line:
            nested_level -= 1
            if nested_level == 0 and in_dcl:
                # Check if volatile is used
                volatile_found = 'volatile' in '\n'.join(lines[max(0, dcl_start_line-5):dcl_start_line])
                if not volatile_found:
                    issues.append(Issue(
                        rule_id="G.CON.04",
                        rule_name="避免使用不正确形式的双重检查锁",
                        file_path=file_path,
                        line_number=dcl_start_line + 1,
                        code_snippet=extract_code_snippet(lines, dcl_start_line),
                        details="双重检查锁模式需要使用volatile关键字来保证线程安全"
                    ))
                in_dcl = False
    return issues


@register_rule("G.CON.14", "线程池中的线程结束后必须清理自定义的ThreadLocal变量")
def check_threadlocal_cleanup(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    threadlocal_pattern = re.compile(r'ThreadLocal\s*<')
    remove_pattern = re.compile(r'\.remove\(\)')

    tl_variables = set()
    tl_remove_found = set()

    # Find ThreadLocal variables
    for i, line in enumerate(lines):
        tl_match = threadlocal_pattern.search(line)
        if tl_match:
            # Try to extract variable name
            var_match = re.search(r'(\w+)\s*=', line)
            if var_match:
                tl_variables.add(var_match.group(1))
        # Check for remove calls
        for var in tl_variables:
            if var in line and remove_pattern.search(line):
                tl_remove_found.add(var)

    # Check for ThreadLocals that were never removed
    for var in tl_variables - tl_remove_found:
        for i, line in enumerate(lines):
            if var in line and 'ThreadLocal' in line:
                issues.append(Issue(
                    rule_id="G.CON.14",
                    rule_name="线程池中的线程结束后必须清理自定义的ThreadLocal变量",
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=extract_code_snippet(lines, i),
                    details=f"ThreadLocal变量 '{var}' 建议在线程结束前调用remove()清理，防止内存泄漏"
                ))
                break
    return issues


@register_rule("G.LOG.05", "禁止直接使用外部数据记录日志")
def check_external_data_logging(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    log_pattern = re.compile(r'(logger|log|Logging)\.(debug|info|warn|error|fatal|trace)')

    for i, line in enumerate(lines):
        if log_pattern.search(line):
            # 检查日志中是否有直接的变量拼接
            if '+' in line:
                # 简单检查：如果有加号且不在字符串内，可能是变量拼接
                issues.append(Issue(
                    rule_id="G.LOG.05",
                    rule_name="禁止直接使用外部数据记录日志",
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=extract_code_snippet(lines, i),
                    details="日志中检测到变量拼接，建议对外部数据进行验证或过滤后再记录日志"
                ))
    return issues


@register_rule("G.LOG.06", "禁止在日志中记录口令、密钥等敏感信息")
def check_sensitive_logging(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    sensitive_words = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential']
    log_pattern = re.compile(r'(logger|log|Logging)\.(debug|info|warn|error|fatal|trace)')

    for i, line in enumerate(lines):
        if log_pattern.search(line):
            for word in sensitive_words:
                if word.lower() in line.lower():
                    issues.append(Issue(
                        rule_id="G.LOG.06",
                        rule_name="禁止在日志中记录口令、密钥等敏感信息",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details=f"日志语句中包含敏感词 '{word}'，可能导致敏感信息泄露"
                    ))
                    break
    return issues


@register_rule("G.EDV.01", "禁止直接使用外部数据来拼接SQL语句")
def check_sql_injection(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE', 'JOIN']
    concat_patterns = [
        r'"[^"]*"\s*\+\s*[\w]+',  # "string" + var
        r'[\w]+\s*\+\s*"[^"]*"',  # var + "string"
    ]

    for i, line in enumerate(lines):
        has_sql = any(keyword.upper() in line.upper() for keyword in sql_keywords)
        if has_sql:
            for pattern in concat_patterns:
                if re.search(pattern, line):
                    issues.append(Issue(
                        rule_id="G.EDV.01",
                        rule_name="禁止直接使用外部数据来拼接SQL语句",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details="SQL语句拼接检测，建议使用PreparedStatement和参数化查询以防止SQL注入"
                    ))
                    break
    return issues


@register_rule("G.EDV.03", "禁止向Runtime.exec()方法或java.lang.ProcessBuilder类传递外部数据")
def check_command_injection(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    patterns = [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*([^)]*)\)', 'Runtime.exec'),
        (r'new\s+ProcessBuilder\s*\(\s*([^)]*)\)', 'ProcessBuilder'),
    ]

    for i, line in enumerate(lines):
        for pattern, method_name in patterns:
            match = re.search(pattern, line)
            if match:
                args = match.group(1)
                # Check if variable is used
                if re.search(r'[a-zA-Z_]\w*\s*[,)]', args):
                    issues.append(Issue(
                        rule_id="G.EDV.03",
                        rule_name="禁止向Runtime.exec()方法或java.lang.ProcessBuilder类传递外部数据",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details=f"{method_name}使用外部变量检测，建议对命令参数进行严格验证或使用白名单"
                    ))
                    break
    return issues


@register_rule("G.PRM.07", "进行IO类操作时，必须在try-with-resource或finally里关闭资源")
def check_resource_closing(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    resource_classes = [
        'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
        'BufferedReader', 'BufferedWriter', 'InputStream', 'OutputStream',
        'Socket', 'ServerSocket', 'Connection', 'Statement', 'ResultSet'
    ]

    try_with_resources = re.compile(r'try\s*\(')

    for i, line in enumerate(lines):
        if any(cls in line for cls in resource_classes):
            # Check if it's a declaration
            if '=' in line and any(cls in line for cls in resource_classes):
                # Check backwards for try-with-resources
                in_try_block = False
                has_finally = False
                has_close = False
                # Simple check: see if it's inside try-with-resources
                check_back = min(10, i)
                context = '\n'.join(lines[max(0, i-check_back):i+1])
                if not try_with_resources.search(context):
                    issues.append(Issue(
                        rule_id="G.PRM.07",
                        rule_name="进行IO类操作时，必须在try-with-resource或finally里关闭资源",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details="资源打开后建议使用try-with-resources语句，以确保资源被正确关闭"
                    ))
    return issues


@register_rule("G.SER.08", "禁止直接将外部数据进行反序列化")
def check_unsafe_deserialization(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    patterns = [
        r'ObjectInputStream',
        r'readObject\(\)',
        r'readUnshared\(\)',
        r'XMLDecoder',
    ]

    for i, line in enumerate(lines):
        if any(p in line for p in patterns):
            issues.append(Issue(
                rule_id="G.SER.08",
                rule_name="禁止直接将外部数据进行反序列化",
                file_path=file_path,
                line_number=i + 1,
                code_snippet=extract_code_snippet(lines, i),
                details="反序列化外部数据存在安全风险，建议使用安全的序列化框架或对输入进行严格验证"
            ))
    return issues


@register_rule("G.TYP.01", "进行数值运算时，避免整数溢出")
def check_integer_overflow(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    overflow_patterns = [
        r'[+-/*%]\s*[\w]+\s*[=]',  # 复合赋值操作
        r'\*\s*\d+\s*[>|<]',       # 乘法运算比较
        r'[+-]\s*[\w]+\s*[>|<]',    # 加减运算比较
    ]

    for i, line in enumerate(lines):
        if any(re.search(pattern, line) for pattern in overflow_patterns):
            # 检查是否有溢出检查
            has_check = any(check in line for check in ['Math.', 'Integer.', 'Long.', 'MAX_VALUE', 'MIN_VALUE'])
            if not has_check:
                issues.append(Issue(
                    rule_id="G.TYP.01",
                    rule_name="进行数值运算时，避免整数溢出",
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=extract_code_snippet(lines, i),
                    details="数值运算可能会导致整数溢出，建议使用安全的运算方法（如Math类方法）或添加溢出检查"
                ))
    return issues


@register_rule("G.TYP.02", "确保除法运算和模运算中的除数不为0")
def check_divide_by_zero(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    division_patterns = [r'\b(\w+)\s*[/%]\s*', r'[/%]\s*(\w+)\b']

    for i, line in enumerate(lines):
        stripped_line = line.strip()

        # Skip comments
        if stripped_line.startswith('//') or stripped_line.startswith('/*') or stripped_line.startswith('*'):
            continue

        for pattern in division_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                var_name = match.group(1)
                # Skip if it's just text like "Empty" in comments (we already skipped comments)
                if var_name.isupper() or len(var_name) <= 2:
                    continue

                # 检查是否有除以零的保护
                has_protection = any(check in line for check in [
                    rf'{var_name}\s*!=\s*0',
                    rf'0\s*!=\s*{var_name}',
                    rf'{var_name}\s*>\s*0',
                    rf'{var_name}\s*<\s*0'
                ])
                if not has_protection:
                    issues.append(Issue(
                        rule_id="G.TYP.02",
                        rule_name="确保除法运算和模运算中的除数不为0",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details=f"变量 '{var_name}' 作为除数，建议添加检查确保其不为0"
                    ))
    return issues


@register_rule("G.EDV.09", "禁止直接使用外部数据作为反射操作中的类名/方法名")
def check_reflection_security(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    reflection_patterns = [
        r'Class\s*\.\s*forName',
        r'Class\s*\.\s*getMethod',
        r'Class\s*\.\s*getField',
        r'Class\s*\.\s*getDeclaredMethod',
        r'Class\s*\.\s*getDeclaredField',
        r'Constructor\s*\.\s*newInstance',
        r'Method\s*\.\s*invoke',
        r'Field\s*\.\s*[get|set]'
    ]

    for i, line in enumerate(lines):
        if any(pattern in line for pattern in reflection_patterns):
            issues.append(Issue(
                rule_id="G.EDV.09",
                rule_name="禁止直接使用外部数据作为反射操作中的类名/方法名",
                file_path=file_path,
                line_number=i + 1,
                code_snippet=extract_code_snippet(lines, i),
                details="反射操作使用外部数据存在安全风险，建议使用白名单或严格的验证"
            ))
    return issues


@register_rule("G.SER.06", "序列化操作要防止敏感信息泄露")
def check_sensitive_serialization(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    if 'implements Serializable' in content:
        sensitive_fields = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential']
        for i, line in enumerate(lines):
            for field in sensitive_fields:
                if field in line.lower() and 'transient' not in line:
                    issues.append(Issue(
                        rule_id="G.SER.06",
                        rule_name="序列化操作要防止敏感信息泄露",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details=f"字段 '{field}' 包含敏感信息但未标记为transient，可能导致序列化时信息泄露"
                    ))
    return issues


@register_rule("G.ERR.04", "防止通过异常泄露敏感信息")
def check_exception_info_leak(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    patterns = [
        (r'catch\s*\([^)]*Exception[^)]*\)\s*\{[^}]*printStackTrace', 'printStackTrace'),
        (r'catch\s*\([^)]*Exception[^)]*\)\s*\{[^}]*getMessage', 'getMessage'),
    ]

    for i, line in enumerate(lines):
        for pattern, method_name in patterns:
            if re.search(pattern, line, re.DOTALL | re.IGNORECASE):
                issues.append(Issue(
                    rule_id="G.ERR.04",
                    rule_name="防止通过异常泄露敏感信息",
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=extract_code_snippet(lines, i),
                    details=f"异常的{method_name}可能包含敏感信息，建议不要直接向用户暴露"
                ))
                break
    return issues


@register_rule("G.OTH.01", "安全场景下必须使用密码学意义上的安全随机数")
def check_secure_random(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    # Check for java.util.Random usage
    random_pattern = re.compile(r'\bRandom\b')
    secure_random_pattern = re.compile(r'SecureRandom')

    for i, line in enumerate(lines):
        if 'java.util.Random' in line or ('Random' in line and 'SecureRandom' not in line and 'import' not in line):
            # Check if it's being used in a security context
            issues.append(Issue(
                rule_id="G.OTH.01",
                rule_name="安全场景下必须使用密码学意义上的安全随机数",
                file_path=file_path,
                line_number=i + 1,
                code_snippet=extract_code_snippet(lines, i),
                details="使用java.util.Random检测，在安全场景下建议使用java.security.SecureRandom"
            ))
    return issues


@register_rule("G.OTH.03", "禁止代码中包含公网地址")
def check_public_addresses(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    patterns = [
        (r'https?://[\w.-]+\.[a-zA-Z]{2,}', 'URL'),
        (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP地址'),
    ]

    exclude_hosts = ['localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'test.com']

    for i, line in enumerate(lines):
        for pattern, addr_type in patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                addr = match.group(0)
                if not any(exclude in addr for exclude in exclude_hosts):
                    issues.append(Issue(
                        rule_id="G.OTH.03",
                        rule_name="禁止代码中包含公网地址",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details=f"硬编码{addr_type} '{addr}' 检测，建议使用配置文件或环境变量"
                    ))
    return issues


@register_rule("G.FIO.01", "使用外部数据构造的文件路径前必须进行校验，校验前必须对文件路径进行规范化处理")
def check_file_path_validation(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    file_construct_patterns = [
        r'new\s+File\s*\([^)]*\)',
        r'File\s*\.\s*createTempFile',
        r'Paths\s*\.\s*get',
        r'Files\s*\.\s*[a-zA-Z_]+'
    ]

    for i, line in enumerate(lines):
        for pattern in file_construct_patterns:
            if re.search(pattern, line):
                # 检查是否有规范化检查
                has_normalization = any(check in line for check in ['normalize', 'getCanonicalPath', 'getCanonicalFile'])
                if not has_normalization:
                    issues.append(Issue(
                        rule_id="G.FIO.01",
                        rule_name="使用外部数据构造的文件路径前必须进行校验，校验前必须对文件路径进行规范化处理",
                        file_path=file_path,
                        line_number=i + 1,
                        code_snippet=extract_code_snippet(lines, i),
                        details="使用外部数据构造文件路径时，建议先进行路径规范化处理（如getCanonicalPath）和安全检查"
                    ))
    return issues


@register_rule("G.FIO.02", "从ZipInputStream中解压文件必须进行安全检查")
def check_zip_safety(content: str, file_path: str) -> List[Issue]:
    issues = []
    lines = content.split("\n")

    zip_pattern = re.compile(r'ZipInputStream|ZipFile')
    check_pattern = re.compile(r'\.\.|getCanonicalPath|normalize')

    for i, line in enumerate(lines):
        if zip_pattern.search(line):
            # Check if there are path validation checks
            context = '\n'.join(lines[max(0, i-5):i+20])
            if not check_pattern.search(context):
                issues.append(Issue(
                    rule_id="G.FIO.02",
                    rule_name="从ZipInputStream中解压文件必须进行安全检查",
                    file_path=file_path,
                    line_number=i + 1,
                    code_snippet=extract_code_snippet(lines, i),
                    details="Zip文件解压未检测到路径验证，建议验证文件路径，防止Zip Slip攻击"
                ))
    return issues


# ============================================================================
# SCANNER ENGINE
# ============================================================================

class JavaCodeScanner:
    """Main scanner class."""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.enabled_rules = set(self.config.get('rules', {}).keys()) or set(RULE_REGISTRY.keys())
        self.exclude_dirs = set(self.config.get('excludeDirs', [
            'target', 'build', '.git', 'node_modules', 'test', 'tests'
        ]))
        self.exclude_patterns = [re.compile(p) for p in self.config.get('excludePatterns', [r'\.class$'])]

    def should_include_file(self, file_path: str) -> bool:
        """Check if file should be included in scan."""
        if not file_path.endswith('.java'):
            return False
        for pattern in self.exclude_patterns:
            if pattern.search(file_path):
                return False
        return True

    def should_include_dir(self, dir_name: str) -> bool:
        """Check if directory should be included."""
        return dir_name not in self.exclude_dirs

    def scan_file(self, file_path: str) -> List[Issue]:
        """Scan a single Java file."""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            for rule_id, (rule_name, rule_func) in RULE_REGISTRY.items():
                if rule_id not in self.enabled_rules:
                    continue
                try:
                    file_issues = rule_func(content, file_path)
                    issues.extend(file_issues)
                except Exception as e:
                    pass

        except Exception as e:
            pass
        return issues

    def scan_directory(self, root_dir: str) -> ScanResult:
        """Scan all Java files in a directory tree."""
        result = ScanResult()

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Filter directories
            dirnames[:] = [d for d in dirnames if self.should_include_dir(d)]

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                if self.should_include_file(file_path):
                    result.files_scanned += 1
                    result.scanned_files.append(file_path)  # Collect scanned file path
                    issues = self.scan_file(file_path)
                    for issue in issues:
                        result.issues.append(issue)
                        result.rule_counts[issue.rule_id] = result.rule_counts.get(issue.rule_id, 0) + 1

        result.total_issues = len(result.issues)
        return result


def generate_markdown_report(result: ScanResult) -> str:
    """Generate a Markdown report from scan results."""
    lines = []
    lines.append("# Java 代码规范扫描报告\n")
    lines.append(f"**扫描日期**: {os.popen('date /t').read().strip() if os.name == 'nt' else os.popen('date').read().strip()}\n")
    lines.append("---\n\n")

    lines.append("## 摘要\n")
    lines.append(f"- **扫描文件数**: {result.files_scanned}\n")
    lines.append(f"- **发现问题数**: {result.total_issues}\n")

    if result.rule_counts:
        lines.append("\n### 按规则统计\n")
        lines.append("| 规则ID | 规则名称 | 问题数 |\n")
        lines.append("|--------|----------|--------|\n")
        for rule_id, count in sorted(result.rule_counts.items()):
            rule_name = RULE_REGISTRY.get(rule_id, (rule_id,))[0]
            lines.append(f"| {rule_id} | {rule_name} | {count} |\n")

    lines.append("\n---\n\n")
    lines.append("## 扫描文件清单\n")
    if result.scanned_files:
        for file_path in sorted(result.scanned_files):
            lines.append(f"- {file_path}\n")
    else:
        lines.append("无 Java 文件被扫描\n")

    lines.append("\n---\n\n")
    lines.append("## 详细问题列表\n")

    if not result.issues:
        lines.append("\n🎉 **未发现任何问题！** 代码符合规范。\n")
    else:
        # Group issues by file
        issues_by_file = defaultdict(list)
        for issue in result.issues:
            issues_by_file[issue.file_path].append(issue)

        for file_path in sorted(issues_by_file.keys()):
            lines.append(f"\n### 文件: {file_path}\n")
            file_issues = issues_by_file[file_path]

            for issue in file_issues:
                lines.append(f"\n#### {issue.rule_id}: {issue.rule_name}\n")
                lines.append(f"- **行号**: {issue.line_number}\n")
                lines.append(f"- **详情**: {issue.details}\n")
                lines.append("\n```java\n")
                lines.append(issue.code_snippet)
                lines.append("\n```\n")
                lines.append("---\n")

    lines.append("\n---\n")
    lines.append("\n## 说明\n")
    lines.append("\n本报告基于预定义的Java代码规范规则自动生成。")
    lines.append(" 建议修复报告中的问题以提高代码质量和安全性。\n")

    return '\n'.join(lines)


def load_config(config_path: str) -> Optional[Dict]:
    """Load configuration from JSON file."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return None


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Java代码规范扫描器')
    parser.add_argument('path', nargs='?', default='.', help='要扫描的目录或文件')
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--output', '-o', help='输出报告文件路径')

    args = parser.parse_args()

    config = None
    if args.config:
        config = load_config(args.config)
    else:
        # Look for config in current directory
        for config_name in ['.java-scanner-config.json', 'java-scanner-config.json']:
            if os.path.exists(config_name):
                config = load_config(config_name)
                break

    scanner = JavaCodeScanner(config)

    target_path = args.path
    if not os.path.exists(target_path):
        print(f"错误: 路径不存在: {target_path}")
        return 1

    print(f"开始扫描: {target_path}")
    if os.path.isfile(target_path):
        result = ScanResult()
        if scanner.should_include_file(target_path):
            result.files_scanned = 1
            result.scanned_files = [target_path]
            result.issues = scanner.scan_file(target_path)
            result.total_issues = len(result.issues)
            for issue in result.issues:
                result.rule_counts[issue.rule_id] = result.rule_counts.get(issue.rule_id, 0) + 1
    else:
        result = scanner.scan_directory(target_path)

    print(f"扫描完成！扫描 {result.files_scanned} 个文件，发现 {result.total_issues} 个问题。")

    report = generate_markdown_report(result)

    # Determine output path - default to scan_report.md in the scanned directory
    if args.output:
        output_path = args.output
    else:
        if os.path.isfile(target_path):
            output_path = "scan_report.md"
        else:
            output_path = os.path.join(target_path, "scan_report.md")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"报告已保存到: {output_path}")

    return 0 if result.total_issues == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
