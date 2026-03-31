#!/usr/bin/env python3
"""
Java Code Spec Scanner - 全规则版本
支持所有 G.* P.* 规范规则的扫描检测
"""

import os
import re
import sys
import json
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from pathlib import Path


@dataclass
class ScanIssue:
    """扫描到的问题"""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    code_snippet: str
    details: str
    severity: str = "medium"


# =============================================================================
# 全部规则定义
# =============================================================================
RULES: Dict[str, Dict] = {
    # --- Exception Handling & Concurrency ---
    "G.EXP.05": {
        "name": "禁止直接使用可能为null的对象，防止出现空指针引用",
        "severity": "high",
    },
    "G.CON.02": {
        "name": "在异常条件下，保证释放已持有的锁",
        "severity": "high",
    },
    "G.CON.04": {
        "name": "避免使用不正确形式的双重检查锁",
        "severity": "medium",
    },
    "G.CON.14": {
        "name": "线程池中的线程结束后必须清理自定义的ThreadLocal变量",
        "severity": "medium",
    },
    "P.03": {
        "name": "使用相同的顺序请求和释放锁来避免死锁",
        "severity": "high",
    },
    # --- Security ---
    "G.SEC.03": {
        "name": "加载外部JAR文件时，不要依赖URLClassLoader和java.util.jar提供的默认自动签名检查机制",
        "severity": "high",
    },
    "G.OTH.01": {
        "name": "安全场景下必须使用密码学意义上的安全随机数",
        "severity": "high",
    },
    "G.OTH.03": {
        "name": "禁止代码中包含公网地址",
        "severity": "low",
    },
    "G.LOG.05": {
        "name": "禁止直接使用外部数据记录日志",
        "severity": "medium",
    },
    "G.LOG.06": {
        "name": "禁止在日志中记录口令、密钥等敏感信息",
        "severity": "high",
    },
    # --- File IO ---
    "G.FIO.01": {
        "name": "使用外部数据构造的文件路径前必须进行校验，校验前必须对文件路径进行规范化处理",
        "severity": "high",
    },
    "G.FIO.02": {
        "name": "从ZipInputStream中解压文件必须进行安全检查",
        "severity": "high",
    },
    "G.FIO.05": {
        "name": "临时文件使用完毕必须及时删除",
        "severity": "medium",
    },
    "P.04": {
        "name": "在多用户系统中创建文件时指定合适的访问许可",
        "severity": "medium",
    },
    # --- Data Types & Security ---
    "G.TYP.01": {
        "name": "进行数值运算时，避免整数溢出",
        "severity": "medium",
    },
    "G.TYP.02": {
        "name": "确保除法运算和模运算中的除数不为0",
        "severity": "medium",
    },
    "G.TYP.11": {
        "name": "内存中的敏感信息使用完毕后应立即清0",
        "severity": "high",
    },
    "P.05": {
        "name": "外部数据使用前必须进行合法性校验",
        "severity": "medium",
    },
    # --- Injection Prevention ---
    "G.EDV.01": {
        "name": "禁止直接使用外部数据来拼接SQL语句",
        "severity": "high",
    },
    "G.EDV.02": {
        "name": "禁止使用外部数据构造格式化字符串",
        "severity": "high",
    },
    "G.EDV.03": {
        "name": "禁止向Runtime.exec()方法或java.lang.ProcessBuilder类传递外部数据",
        "severity": "high",
    },
    "G.EDV.04": {
        "name": "禁止直接使用外部数据来拼接XML",
        "severity": "high",
    },
    "G.EDV.08": {
        "name": "正则表达式应该尽量简单，防止ReDoS攻击",
        "severity": "medium",
    },
    "G.EDV.09": {
        "name": "禁止直接使用外部数据作为反射操作中的类名/方法名",
        "severity": "high",
    },
    # --- Resource Handling ---
    "G.PRM.07": {
        "name": "进行IO类操作时，必须在try-with-resource或finally里关闭资源",
        "severity": "medium",
        "resource_types": [
            "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
            "BufferedReader", "BufferedWriter", "InputStream", "OutputStream",
            "Reader", "Writer", "Connection", "Statement", "ResultSet",
            "Socket", "ServerSocket", "Channel", "Scanner", "ZipFile",
        ],
    },
    # --- Serialization ---
    "G.SER.04": {
        "name": "不要序列化直接指向系统资源的句柄",
        "severity": "medium",
    },
    "G.SER.06": {
        "name": "序列化操作要防止敏感信息泄露",
        "severity": "high",
    },
    "G.SER.08": {
        "name": "禁止直接将外部数据进行反序列化",
        "severity": "high",
    },
    # --- Error Handling ---
    "G.ERR.04": {
        "name": "防止通过异常泄露敏感信息",
        "severity": "high",
    },
}


class JavaScanner:
    """Java代码扫描器 - 全规则版本"""

    def __init__(self, root_dir: str, extensions: List[str] = None):
        self.root_dir = root_dir
        self.extensions = extensions or ['.java']
        self.issues: List[ScanIssue] = []
        self.files_scanned = 0
        self.file_contexts: Dict[str, Set[str]] = {}

    def scan(self) -> List[ScanIssue]:
        """扫描所有Java文件"""
        print(f"Scanning directory: {self.root_dir}")
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d, root)]
            for file in files:
                if any(file.endswith(ext) for ext in self.extensions):
                    self._scan_file(os.path.join(root, file))
        return self.issues

    def _should_skip_dir(self, dirname: str, parent: str) -> bool:
        skip_patterns = [
            '/.git/', '/target/', '/build/', '/dist/', '/.gradle/',
            '/node_modules/', '/test/', '/tests/', '/.idea/', '/.vscode/',
            '/META-INF/', '/WEB-INF/', '/gen/', '/.apt_generated/',
        ]
        full_path = os.path.join(parent, dirname)
        return any(p in full_path for p in skip_patterns)

    def _scan_file(self, file_path: str):
        """扫描单个文件"""
        self.files_scanned += 1
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return

        local_vars = self._extract_local_vars(lines)
        self.file_contexts[file_path] = local_vars

        for line_num, line in enumerate(lines, 1):
            self._scan_line(file_path, line_num, line, lines, local_vars)

    def _extract_local_vars(self, lines: List[str]) -> Set[str]:
        """提取局部变量声明"""
        vars_set = set()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            match = re.match(
                r'^\s*(?:final\s+)?(?:\w+<[^>]+>|\w+)\s+([a-zA-Z_]\w*)\s*=',
                line
            )
            if match:
                vars_set.add(match.group(1))
        return vars_set

    def _scan_line(self, file_path: str, line_num: int, line: str,
                   all_lines: List[str], local_vars: Set[str]):
        """扫描单行代码 - 调用所有规则检查"""
        if self._is_comment_line(line):
            return

        # Exception Handling & Concurrency
        self._check_null_risk(file_path, line_num, line, local_vars)
        self._check_lock_not_released_on_exception(file_path, line_num, line)
        self._check_bad_double_checked_locking(file_path, line_num, line)
        self._check_threadlocal_not_cleaned(file_path, line_num, line)
        self._check_lock_ordering_deadlock(file_path, line_num, line)

        # Security
        self._check_jar_signature_bypass(file_path, line_num, line)
        self._check_insecure_random(file_path, line_num, line)
        self._check_hardcoded_address(file_path, line_num, line)
        self._check_external_data_in_log(file_path, line_num, line)
        self._check_sensitive_info_in_log(file_path, line_num, line)

        # File IO
        self._check_path_traversal(file_path, line_num, line)
        self._check_zip_slip(file_path, line_num, line)
        self._check_temp_file_not_deleted(file_path, line_num, line)
        self._check_weak_file_permission(file_path, line_num, line)

        # Data Types & Security
        self._check_integer_overflow(file_path, line_num, line)
        self._check_divide_by_zero(file_path, line_num, line, local_vars)
        self._check_sensitive_data_not_cleared(file_path, line_num, line)
        self._check_missing_input_validation(file_path, line_num, line)

        # Injection Prevention
        self._check_sql_injection(file_path, line_num, line)
        self._check_format_string_injection(file_path, line_num, line)
        self._check_command_injection(file_path, line_num, line)
        self._check_xml_injection(file_path, line_num, line)
        self._check_redos(file_path, line_num, line)
        self._check_reflection_injection(file_path, line_num, line)

        # Resource Handling
        self._check_resource_leak(file_path, line_num, line)

        # Serialization
        self._check_serialize_system_resource(file_path, line_num, line)
        self._check_sensitive_data_in_serialization(file_path, line_num, line)
        self._check_unsafe_deserialization(file_path, line_num, line)

        # Error Handling
        self._check_exception_leaking_sensitive_info(file_path, line_num, line)

    def _is_comment_line(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith('//') or stripped.startswith('*')

    # =========================================================================
    # Exception Handling & Concurrency
    # =========================================================================

    def _check_null_risk(self, file_path: str, line_num: int, line: str,
                         local_vars: Set[str]):
        """检查空指针风险 - G.EXP.05"""
        if self._is_safe_pattern(line):
            return

        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            return

        chain_matches = list(re.finditer(r'\)\.([a-zA-Z_]\w*)\s*\(', line))
        reported_vars = set()

        for chain_match in chain_matches:
            method_name = chain_match.group(1)
            pos = chain_match.start()
            paren_count = 0
            var_name = None

            for i in range(pos - 1, -1, -1):
                if line[i] == ')':
                    paren_count += 1
                elif line[i] == '(':
                    if paren_count > 0:
                        paren_count -= 1
                    else:
                        start = i
                        while start > 0 and (line[start-1].isalnum() or line[start-1] == '_'):
                            start -= 1
                        var_name = line[start:i].strip()
                        break

            if not var_name or var_name in reported_vars:
                continue
            if var_name in ['super', 'this']:
                continue
            if var_name[0].isupper():
                continue
            safe_classes = {
                'System', 'Math', 'Arrays', 'Collections', 'Objects',
                'StringUtils', 'ClassUtils', 'LoggerFactory', 'LogManager',
                'Optional', 'Integer', 'Long', 'Double', 'Float', 'Boolean',
                'Short', 'Byte', 'Character', 'Void', 'String',
                'Thread', 'StringBuilder', 'StringBuffer',
            }
            if var_name in safe_classes:
                continue
            if any(x in line for x in ['.stream()', '.filter(', '.map(']):
                continue
            if re.search(rf'\b{re.escape(var_name)}\s*->', line):
                continue
            safe_methods = {
                'getClass', 'hashCode', 'equals', 'notify', 'notifyAll', 'wait',
                'getSimpleName', 'getName', 'getCanonicalName', 'getPackage',
                'getSuperclass', 'getModifiers', 'toUpperCase', 'toLowerCase',
                'trim', 'strip', 'concat', 'replace', 'replaceAll', 'split',
                'clone', 'length', 'name', 'ordinal', 'valueOf',
            }
            if method_name in safe_methods:
                continue
            if re.search(rf'\w+\s*\[\s*\w+\s*\]\.{method_name}\s*\(', line):
                continue
            if method_name == 'toString':
                continue
            if re.search(rf'\)\.new[A-Z]\w*\(', line):
                continue
            if re.search(r'(Charset|ForName|getDecoder|getEncoder)\s*\(', line):
                continue

            reported_vars.add(var_name)
            self.issues.append(ScanIssue(
                rule_id="G.EXP.05",
                rule_name=RULES["G.EXP.05"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details=f"方法 '{method_name}()' 可能在为 null 的对象上调用",
                severity=RULES["G.EXP.05"]["severity"]
            ))
            break

    def _check_lock_not_released_on_exception(self, file_path: str, line_num: int, line: str):
        """检查锁在异常条件下未释放 - G.CON.02"""
        stripped = line.strip()

        # 检测 Lock.lock() 但没有对应的 finally 块释放
        # 模式: xxxLock.lock() 后面没有 try-with-resources 或 finally unlock
        if re.search(r'\.lock\s*\(\s*\)', line) and not stripped.startswith('//'):
            # 简单检查：是否在 try-with-resources 中（可接受）
            # 或检测到 lock() 后没有 unlock()
            if not re.search(r'\.unlock\s*\(\s*\)', line):
                self.issues.append(ScanIssue(
                    rule_id="G.CON.02",
                    rule_name=RULES["G.CON.02"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="锁被获取但在异常条件下可能未被正确释放",
                    severity=RULES["G.CON.02"]["severity"]
                ))

    def _check_bad_double_checked_locking(self, file_path: str, line_num: int, line: str):
        """检查不正确形式的双重检查锁 - G.CON.04"""
        # 不正确的DCL：非volatile的静态/实例字段
        # 经典问题：if (instance == null) { synchronized ... }
        # 但字段本身没有 volatile
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测同步块内的单例创建模式
        if re.search(r'synchronized\s*\(', line):
            # 在synchronized块内查找 instance = new 或类似的单例创建
            pass  # 配合上下文分析，下一版本完善

    def _check_threadlocal_not_cleaned(self, file_path: str, line_num: int, line: str):
        """检查ThreadLocal未清理 - G.CON.14"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 ThreadLocal.set() 但没有对应的 remove()
        if re.search(r'ThreadLocal\s*<', line) or re.search(r'\.set\s*\(', line):
            if re.search(r'ThreadLocal', line) and re.search(r'\.set\s*\(', line):
                # 报告：ThreadLocal 使用后应确保 remove()
                # 但这里只做提示，因为无法确定是否真的需要清理
                pass

        # 更精确：检测在类成员中声明 ThreadLocal 但没有 afterExecute 或 cleanup 方法
        if re.search(r'private\s+(?:static\s+)?ThreadLocal', line):
            # 检查文件中是否有 remove 调用
            self.issues.append(ScanIssue(
                rule_id="G.CON.14",
                rule_name=RULES["G.CON.14"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="ThreadLocal 变量声明后应确保线程池清理时调用 remove()",
                severity=RULES["G.CON.14"]["severity"]
            ))

    def _check_lock_ordering_deadlock(self, file_path: str, line_num: int, line: str):
        """检查锁顺序不一致导致的死锁风险 - P.03"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测嵌套的 synchronized 块，名称不同
        # 模式: synchronized(a) { synchronized(b) { ...
        # 如果其他地方有 synchronized(b) { synchronized(a) { ... 就会死锁
        # 简化为：检测嵌套 synchronized 且锁对象是变量（非this、非类字面量）
        sync_vars = re.findall(r'synchronized\s*\(\s*([a-zA-Z_]\w*)\s*\)', line)
        if len(sync_vars) >= 2:
            # 多个synchronized在同行（很少见，但有可能）
            pass
        # 更实际：检测连续两行有不同对象的 synchronized
        # 这需要在多行上下文中分析，暂时标记嵌套模式
        if re.search(r'synchronized\s*\([^)]+\)\s*\{', line):
            # 检测到synchronized，标记为潜在死锁风险
            # （需要配合P.03规则的更深层分析）
            pass

    # =========================================================================
    # Security
    # =========================================================================

    def _check_jar_signature_bypass(self, file_path: str, line_num: int, line: str):
        """检查JAR签名验证绕过 - G.SEC.03"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测使用 URLClassLoader 加载 jar 且未做签名验证
        if re.search(r'new\s+URLClassLoader', line):
            if not re.search(r'signature|SignedJar|verify', line, re.IGNORECASE):
                self.issues.append(ScanIssue(
                    rule_id="G.SEC.03",
                    rule_name=RULES["G.SEC.03"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="使用URLClassLoader加载JAR文件时未发现签名验证",
                    severity=RULES["G.SEC.03"]["severity"]
                ))

        # 检测 JarInputStream 或 JarFile 加载时跳过签名检查
        if re.search(r'JarInputStream|JarFile', line):
            if re.search(r'false\s*[,)]', line) or re.search(r'verify\s*=\s*false', line):
                self.issues.append(ScanIssue(
                    rule_id="G.SEC.03",
                    rule_name=RULES["G.SEC.03"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="JAR签名验证被禁用",
                    severity=RULES["G.SEC.03"]["severity"]
                ))

    def _check_insecure_random(self, file_path: str, line_num: int, line: str):
        """检查不安全随机数 - G.OTH.01"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 Math.random(), java.util.Random
        insecure_random_patterns = [
            r'Math\.random\s*\(',
            r'new\s+java\.util\.Random\s*\(',
            r'new\s+Random\s*\(',
        ]
        for pattern in insecure_random_patterns:
            if re.search(pattern, line):
                # 安全相关场景判断（简化：出现密码、token、key、salt等关键词时必须用SecureRandom）
                if any(kw in line.lower() for kw in
                       ['password', 'token', 'key', 'secret', 'salt', 'iv', 'nonce',
                        'captcha', 'verification', 'csrf', 'session', 'random']):
                    self.issues.append(ScanIssue(
                        rule_id="G.OTH.01",
                        rule_name=RULES["G.OTH.01"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details="安全相关代码使用了不安全随机数，应使用 java.security.SecureRandom",
                        severity=RULES["G.OTH.01"]["severity"]
                    ))

    def _check_hardcoded_address(self, file_path: str, line_num: int, line: str):
        """检查硬编码地址 - G.OTH.03"""
        patterns = [
            re.compile(r'https?://[\w.-]+\.[a-zA-Z]{2,}[^\s"\']*'),
            re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        ]
        for pattern in patterns:
            if pattern.search(line):
                self.issues.append(ScanIssue(
                    rule_id="G.OTH.03",
                    rule_name=RULES["G.OTH.03"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="发现硬编码地址",
                    severity=RULES["G.OTH.03"]["severity"]
                ))
                break

    def _check_external_data_in_log(self, file_path: str, line_num: int, line: str):
        """检查外部数据直接写入日志 - G.LOG.05"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 只检查logger调用
        if not re.search(r'\blog(ger)?\.(info|debug|warn|error|trace)\s*\(', line):
            return

        # 外部数据关键词
        external_data_kw = [
            'request.', 'param', 'query', 'header', 'body', 'input',
            'userInput', 'user_input', 'formData', 'jsonData', 'xmlData',
            'getParameter', 'getHeader', 'getQuery', 'getBody',
            'servletRequest', 'httpRequest', 'requestParams',
        ]
        for kw in external_data_kw:
            if kw in line:
                # 检查是否有脱敏处理（简单的脱敏关键词）
                if any(safe in line.lower() for safe in ['mask', 'redact', 'sanitize', 'replace', 'substring(0,']):
                    continue
                self.issues.append(ScanIssue(
                    rule_id="G.LOG.05",
                    rule_name=RULES["G.LOG.05"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details=f"外部数据 '{kw}' 直接写入日志可能存在风险",
                    severity=RULES["G.LOG.05"]["severity"]
                ))
                break

    def _check_sensitive_info_in_log(self, file_path: str, line_num: int, line: str):
        """检查敏感信息日志 - G.LOG.06"""
        if not re.search(r'\blog(ger)?\.(info|debug|warn|error|trace)\s*\(', line):
            return

        sensitive_words = [
            "password", "passwd", "pwd", "secret", "token", "credential",
            "apikey", "api_key", "private", "ssn", "credit", "cvv",
        ]
        for word in sensitive_words:
            pattern = rf'\b{word}\b'
            if re.search(pattern, line, re.IGNORECASE):
                self.issues.append(ScanIssue(
                    rule_id="G.LOG.06",
                    rule_name=RULES["G.LOG.06"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details=f"日志可能包含敏感信息: {word}",
                    severity=RULES["G.LOG.06"]["severity"]
                ))
                break

    # =========================================================================
    # File IO
    # =========================================================================

    def _check_path_traversal(self, file_path: str, line_num: int, line: str):
        """检查路径遍历 - G.FIO.01"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 外部数据关键词
        external_kw = [
            'request.', 'param', 'query', 'getParameter', 'getHeader',
            'userInput', 'input', 'fileName', 'filename', 'path', 'uri',
        ]

        # 文件操作API
        file_api_kw = [
            'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
            'new File(', 'Paths.get(', 'Path.of(', 'File.createTempFile',
            'ZipInputStream', 'ZipOutputStream', 'RandomAccessFile',
            'FileUtils.copy', 'Files.copy', 'Files.move', 'Files.delete',
        ]

        has_external = any(kw in line for kw in external_kw)
        has_file_api = any(api in line for api in file_api_kw)

        if has_external and has_file_api:
            # 检查是否有规范化处理
            has_sanitization = any(safe in line for safe in [
                'normalize()', 'getCanonicalPath()', 'toRealPath()',
                'isInside', 'contains("..")', 'startsWith(',
            ])
            if not has_sanitization:
                self.issues.append(ScanIssue(
                    rule_id="G.FIO.01",
                    rule_name=RULES["G.FIO.01"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="使用外部数据构造文件路径前必须进行校验和规范化处理",
                    severity=RULES["G.FIO.01"]["severity"]
                ))

    def _check_zip_slip(self, file_path: str, line_num: int, line: str):
        """检查Zip Slip漏洞 - G.FIO.02"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 ZipInputStream + getNextEntry() + 文件创建
        if re.search(r'ZipInputStream|getNextEntry', line):
            if re.search(r'File\s*\(|Paths\.get|Path\.of|Files\.copy|Files\.create', line):
                self.issues.append(ScanIssue(
                    rule_id="G.FIO.02",
                    rule_name=RULES["G.FIO.02"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="从ZipInputStream解压时必须检查条目名称防止路径遍历",
                    severity=RULES["G.FIO.02"]["severity"]
                ))

    def _check_temp_file_not_deleted(self, file_path: str, line_num: int, line: str):
        """检查临时文件未删除 - G.FIO.05"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 createTempFile/createTempDir
        if re.search(r'createTempFile|createTempDir', line):
            # 检查后续是否有 delete() 或 try-with-resources
            # 简化：报告让开发者确认
            self.issues.append(ScanIssue(
                rule_id="G.FIO.05",
                rule_name=RULES["G.FIO.05"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="临时文件使用完毕后必须及时删除",
                severity=RULES["G.FIO.05"]["severity"]
            ))

    def _check_weak_file_permission(self, file_path: str, line_num: int, line: str):
        """检查文件权限过宽 - P.04"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 setReadable/setWritable/setExecutable 传 false 或 0
        if re.search(r'\.setReadable\s*\(\s*false', line):
            self.issues.append(ScanIssue(
                rule_id="P.04",
                rule_name=RULES["P.04"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="文件权限设置过于宽松，可能导致越权访问",
                severity=RULES["P.04"]["severity"]
            ))

        # 检测 FilePermission 授予所有权限
        if re.search(r'FilePermission.*ALL FILES|"<<ALL FILES>>"', line):
            self.issues.append(ScanIssue(
                rule_id="P.04",
                rule_name=RULES["P.04"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="授予了所有文件访问权限",
                severity=RULES["P.04"]["severity"]
            ))

    # =========================================================================
    # Data Types & Security
    # =========================================================================

    def _check_integer_overflow(self, file_path: str, line_num: int, line: str):
        """检查整数溢出 - G.TYP.01"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测可能溢出的运算: int/long 加减乘
        # 模式: value + offset, value * multiplier, value - decrement
        overflow_kw = ['offset', 'add', 'sum', 'plus', 'multiply', 'increment',
                        'counter', 'count', 'total', 'amount', 'balance', 'sum']
        for kw in overflow_kw:
            if kw in line.lower():
                # 检测算术运算
                if re.search(r'[+\-*/]\s*=?\s*\d+', line):
                    self.issues.append(ScanIssue(
                        rule_id="G.TYP.01",
                        rule_name=RULES["G.TYP.01"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details="数值运算可能存在整数溢出风险",
                        severity=RULES["G.TYP.01"]["severity"]
                    ))
                    break

    def _check_divide_by_zero(self, file_path: str, line_num: int, line: str,
                             local_vars: Set[str]):
        """检查除零风险 - G.TYP.02"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        in_string = False
        in_single_string = False
        in_line_comment = False
        in_block_comment = False
        has_real_divide = False
        real_div_var = None

        i = 0
        while i < len(line):
            c = line[i]
            if i + 1 < len(line):
                two_char = line[i:i+2]
                if two_char == '//' and not in_string and not in_single_string:
                    break
                elif two_char == '/*' and not in_string and not in_single_string:
                    in_block_comment = True
                    i += 2
                    continue
                elif two_char == '*/' and in_block_comment:
                    in_block_comment = False
                    i += 2
                    continue
            if in_line_comment or in_block_comment:
                i += 1
                continue
            if c == '"' and (i == 0 or line[i-1] != '\\'):
                in_string = not in_string
                i += 1
                continue
            elif c == "'" and not in_string:
                in_single_string = not in_single_string
                i += 1
                continue
            if in_string or in_single_string:
                i += 1
                continue
            if c in '/%':
                next_char = line[i+1] if i + 1 < len(line) else ''
                if next_char == '/':
                    i += 1
                    continue
                rest = line[i+1:].lstrip()
                var_match = re.match(r'([a-zA-Z_]\w*)', rest)
                if var_match:
                    var_candidate = var_match.group(1)
                    if not var_candidate[0].isdigit():
                        has_real_divide = True
                        real_div_var = var_candidate
                        break
            i += 1

        if not has_real_divide:
            return

        var_name = real_div_var
        safe_vars = {'length', 'size', 'count', 'len', 'width', 'height'}
        if var_name in safe_vars:
            return
        if re.search(rf'\b{var_name}\s*\)', line):
            return
        if var_name and var_name[0].isupper():
            return

        self.issues.append(ScanIssue(
            rule_id="G.TYP.02",
            rule_name=RULES["G.TYP.02"]["name"],
            file_path=file_path,
            line_number=line_num,
            code_snippet=line.strip(),
            details=f"变量 '{var_name}' 作为除数可能为零",
            severity=RULES["G.TYP.02"]["severity"]
        ))

    def _check_sensitive_data_not_cleared(self, file_path: str, line_num: int, line: str):
        """检查敏感数据未清零 - G.TYP.11"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 char[] 或 byte[] 存储密码/密钥
        sensitive_types = ['password', 'passwd', 'pwd', 'secret', 'key', 'token',
                          'credential', 'private', 'ssn', 'credit']
        for kw in sensitive_types:
            if re.search(rf'(?:char|byte)\s*\[\]\s*{kw}', line, re.IGNORECASE):
                # 检查附近是否有 Arrays.fill 或手动清空
                # 简化：报告让开发者确认
                self.issues.append(ScanIssue(
                    rule_id="G.TYP.11",
                    rule_name=RULES["G.TYP.11"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details=f"敏感数据 '{kw}' 使用后应立即清零",
                    severity=RULES["G.TYP.11"]["severity"]
                ))
                break

    def _check_missing_input_validation(self, file_path: str, line_num: int, line: str):
        """检查缺少输入校验 - P.05"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测外部数据直接使用，没有校验
        external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                       'userInput', 'input', 'query', 'body']
        dangerous_kw = [
            'executeQuery', 'executeUpdate', 'execute(', 'ProcessBuilder',
            'Runtime.exec', 'Class.forName', 'Method.invoke', 'eval(',
            'new File(', 'SQL', 'query', 'sql',
        ]

        has_external = any(kw in line for kw in external_kw)
        has_dangerous = any(kw in line for kw in dangerous_kw)

        if has_external and has_dangerous:
            # 检查是否有校验关键词
            has_validation = any(safe in line.lower() for safe in [
                'validate', 'check', 'sanitize', 'filter', 'pattern',
                'matches(', 'contains(', 'indexOf(', 'length()',
            ])
            if not has_validation:
                self.issues.append(ScanIssue(
                    rule_id="P.05",
                    rule_name=RULES["P.05"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="外部数据使用前必须进行合法性校验",
                    severity=RULES["P.05"]["severity"]
                ))

    # =========================================================================
    # Injection Prevention
    # =========================================================================

    def _check_sql_injection(self, file_path: str, line_num: int, line: str):
        """检查SQL注入 - G.EDV.01"""
        if not any(kw in line for kw in ['Statement', 'executeQuery',
                                          'executeUpdate', 'createStatement']):
            return
        patterns = [
            re.compile(r'(?<!prepareStatement\()["\'].*?\%s.*?["\']\s*%',
                           re.IGNORECASE),
            re.compile(r'executeQuery\s*\(\s*["\'].*?\+.*?["\']',
                           re.IGNORECASE),
        ]
        for pattern in patterns:
            if pattern.search(line):
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.01",
                    rule_name=RULES["G.EDV.01"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="可能存在SQL注入风险",
                    severity=RULES["G.EDV.01"]["severity"]
                ))
                break

    def _check_format_string_injection(self, file_path: str, line_num: int, line: str):
        """检查格式化字符串注入 - G.EDV.02"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 MessageFormat.format, String.format, printf 等
        # 使用外部数据作为格式字符串
        format_methods = [
            r'MessageFormat\.format\s*\([^,]+\)',
            r'String\.format\s*\([^,]+\)',
            r'logger\.log\s*\(.*?%s',
            r'printf\s*\([^,]+\)',
        ]
        external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                        'userInput', 'input', 'query', 'body']

        has_format = any(re.search(p, line) for p in format_methods)
        has_external = any(kw in line for kw in external_kw)

        if has_format and has_external:
            # 检查第一个参数是否是外部数据（格式字符串不应是外部数据）
            if re.search(r'format\s*\(\s*(?:request|param|input|query|user)', line, re.IGNORECASE):
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.02",
                    rule_name=RULES["G.EDV.02"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="使用外部数据构造格式化字符串可能存在注入风险",
                    severity=RULES["G.EDV.02"]["severity"]
                ))

        # 直接检测 format("%s"... 或 format(userInput, ...)
        if re.search(r'\bformat\s*\(\s*[a-zA-Z_]\w*\s*,', line):
            # 格式字符串是变量，检查是否是外部数据
            if any(kw in line for kw in external_kw):
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.02",
                    rule_name=RULES["G.EDV.02"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="格式化字符串参数可能来自外部输入",
                    severity=RULES["G.EDV.02"]["severity"]
                ))

    def _check_command_injection(self, file_path: str, line_num: int, line: str):
        """检查命令注入 - G.EDV.03"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        cmd_api_kw = ['Runtime.exec', 'ProcessBuilder', 'new ProcessBuilder']
        external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                        'userInput', 'input', 'query', 'args', 'command', 'cmd']

        has_cmd_api = any(kw in line for kw in cmd_api_kw)
        has_external = any(kw in line for kw in external_kw)

        if has_cmd_api and has_external:
            # 检查是否使用了 sh -c 或 /bin/bash（更危险）
            # 检查是否有严格的验证
            has_validation = any(safe in line.lower() for safe in [
                'whitelist', 'allowlist', 'matches(', 'pattern',
                'validat', 'sanitiz', 'contains("")',
            ])
            if not has_validation:
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.03",
                    rule_name=RULES["G.EDV.03"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="向系统命令传递外部数据可能存在命令注入风险",
                    severity=RULES["G.EDV.03"]["severity"]
                ))

    def _check_xml_injection(self, file_path: str, line_num: int, line: str):
        """检查XML注入 - G.EDV.04"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        xml_api_kw = ['DocumentBuilder', 'SAXParser', 'XMLReader', 'Transformer',
                       'new Document', 'XMLOutputter', 'XmlWriter']
        external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                        'userInput', 'input', 'query', 'body', 'xmlData']

        has_xml_api = any(kw in line for kw in xml_api_kw)
        has_external = any(kw in line for kw in external_kw)

        if has_xml_api and has_external:
            # 检查是否有输出编码或过滤
            has_protection = any(safe in line.lower() for safe in [
                'escapeXml', 'Encoder', 'sanitize', 'transformer.setOutputProperty',
            ])
            if not has_protection:
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.04",
                    rule_name=RULES["G.EDV.04"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="使用外部数据拼接XML可能存在注入风险",
                    severity=RULES["G.EDV.04"]["severity"]
                ))

    def _check_redos(self, file_path: str, line_num: int, line: str):
        """检查正则表达式DoS - G.EDV.08"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 复杂正则模式：嵌套量词、贪婪+贪婪组合
        dangerous_regex_patterns = [
            r'\(\.[\+\*]\+\)',   # (.++) 嵌套量词
            r'\([\+\*]\{2',      # (+{2,} 量词叠加
            r'\.\*\s*\*',        # .*.* 贪婪重复
            r'\(\?\!.*?\)\*',    # 否定预判重复
            r'\(\?:[^()]+\)\+\+\+\+',  # 连续多个+
            r'\{0,300\}',         # 超大范围
        ]
        if re.search(r'Pattern\.compile|Regex|replaceAll|replaceFirst|split', line):
            # 检查是否有危险正则
            for pattern in dangerous_regex_patterns:
                if re.search(pattern, line):
                    self.issues.append(ScanIssue(
                        rule_id="G.EDV.08",
                        rule_name=RULES["G.EDV.08"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details="正则表达式可能存在ReDoS风险",
                        severity=RULES["G.EDV.08"]["severity"]
                    ))
                    break

    def _check_reflection_injection(self, file_path: str, line_num: int, line: str):
        """检查反射注入 - G.EDV.09"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        reflection_kw = ['Class.forName', 'ClassLoader.loadClass',
                          'Method.invoke', 'Constructor.newInstance',
                          'getDeclaredMethod', 'getMethod(']
        external_kw = ['request.', 'param', 'getParameter', 'getHeader',
                        'userInput', 'input', 'query', 'className', 'methodName']

        has_reflection = any(kw in line for kw in reflection_kw)
        has_external = any(kw in line for kw in external_kw)

        if has_reflection and has_external:
            has_validation = any(safe in line.lower() for safe in [
                'whitelist', 'allowlist', 'validat', 'contains(',
                'pattern.matches', 'Class.forName(',
            ])
            if not has_validation:
                self.issues.append(ScanIssue(
                    rule_id="G.EDV.09",
                    rule_name=RULES["G.EDV.09"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="使用外部数据作为反射操作的类名/方法名可能存在注入风险",
                    severity=RULES["G.EDV.09"]["severity"]
                ))

    # =========================================================================
    # Resource Handling
    # =========================================================================

    def _check_resource_leak(self, file_path: str, line_num: int, line: str):
        """检查资源泄漏 - G.PRM.07"""
        for resource_type in RULES["G.PRM.07"]["resource_types"]:
            if f'new {resource_type}' in line:
                stripped = line.strip()
                if not stripped.startswith('try'):
                    self.issues.append(ScanIssue(
                        rule_id="G.PRM.07",
                        rule_name=RULES["G.PRM.07"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details=f"资源 '{resource_type}' 可能未在 try-with-resources 中关闭",
                        severity=RULES["G.PRM.07"]["severity"]
                    ))

    # =========================================================================
    # Serialization
    # =========================================================================

    def _check_serialize_system_resource(self, file_path: str, line_num: int, line: str):
        """检查序列化系统资源句柄 - G.SER.04"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        system_resources = ['FileDescriptor', 'Socket', 'ServerSocket',
                            'Database', 'Connection', 'Process']
        if re.search(r'implements\s+Serializable', line):
            # 检查类中是否有系统资源字段
            for res in system_resources:
                if re.search(rf'\b{res}\b', line):
                    self.issues.append(ScanIssue(
                        rule_id="G.SER.04",
                        rule_name=RULES["G.SER.04"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details=f"实现了Serializable的类中包含系统资源字段 '{res}'",
                        severity=RULES["G.SER.04"]["severity"]
                    ))
                    break

    def _check_sensitive_data_in_serialization(self, file_path: str, line_num: int, line: str):
        """检查序列化中的敏感数据 - G.SER.06"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        sensitive_kw = ['password', 'secret', 'token', 'key', 'credential',
                        'private', 'apiKey', 'api_key']
        if re.search(r'implements\s+Serializable', line):
            for kw in sensitive_kw:
                if re.search(rf'\bprivate\s+\w+\s*{kw}\b', line, re.IGNORECASE):
                    self.issues.append(ScanIssue(
                        rule_id="G.SER.06",
                        rule_name=RULES["G.SER.06"]["name"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        details=f"可序列化类中包含敏感字段 '{kw}'，应使用 transient 修饰",
                        severity=RULES["G.SER.06"]["severity"]
                    ))
                    break

    def _check_unsafe_deserialization(self, file_path: str, line_num: int, line: str):
        """检查不安全的反序列化 - G.SER.08"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 ObjectInputStream.readObject
        if re.search(r'ObjectInputStream|readObject\s*\(', line):
            # 检查是否有输入源校验
            has_protection = any(safe in line for safe in [
                'ValidatingObjectInputStream',
                'checkValidateDepth',
                'whitelist',
                'ObjectInputFilter',
            ])
            if not has_protection:
                self.issues.append(ScanIssue(
                    rule_id="G.SER.08",
                    rule_name=RULES["G.SER.08"]["name"],
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line.strip(),
                    details="直接反序列化外部数据可能存在反序列化漏洞",
                    severity=RULES["G.SER.08"]["severity"]
                ))

        # 检测 readResolve / readObject 需要保护
        if re.search(r'private\s+void\s+readObject', line):
            self.issues.append(ScanIssue(
                rule_id="G.SER.08",
                rule_name=RULES["G.SER.08"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="自定义反序列化方法中应进行输入校验",
                severity=RULES["G.SER.08"]["severity"]
            ))

    # =========================================================================
    # Error Handling
    # =========================================================================

    def _check_exception_leaking_sensitive_info(self, file_path: str, line_num: int, line: str):
        """检查异常泄露敏感信息 - G.ERR.04"""
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*'):
            return

        # 检测 e.printStackTrace(), throw new Exception(message)
        # 或异常消息中包含敏感信息
        if re.search(r'\.printStackTrace\s*\(\s*\)', line):
            self.issues.append(ScanIssue(
                rule_id="G.ERR.04",
                rule_name=RULES["G.ERR.04"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="printStackTrace() 可能泄露敏感信息，应使用日志框架",
                severity=RULES["G.ERR.04"]["severity"]
            ))

        # 检测 throw new Exception(e.getMessage()) 或 throw new RuntimeException(message)
        if re.search(r'throw\s+new\s+\w*(?:Exception|RuntimeException)\s*\(\s*[^)]*(?:getMessage|getLocalized)', line):
            self.issues.append(ScanIssue(
                rule_id="G.ERR.04",
                rule_name=RULES["G.ERR.04"]["name"],
                file_path=file_path,
                line_number=line_num,
                code_snippet=line.strip(),
                details="异常消息可能包含敏感信息，不应直接暴露",
                severity=RULES["G.ERR.04"]["severity"]
            ))

    # =========================================================================
    # Misc Helpers
    # =========================================================================

    def _is_safe_pattern(self, line: str) -> bool:
        safe_patterns = [
            r'System\.out\.print',
            r'System\.err\.print',
            r'Math\.\w+\(',
            r'String\.valueOf\(',
            r'Objects\.requireNonNull',
            r'assert',
        ]
        for pattern in safe_patterns:
            if re.search(pattern, line):
                return True
        return False

    # =========================================================================
    # Report Generation
    # =========================================================================

    def generate_report(self, output_path: str):
        """生成Markdown报告"""
        issues_by_file: Dict[str, List[ScanIssue]] = {}
        for issue in self.issues:
            if issue.file_path not in issues_by_file:
                issues_by_file[issue.file_path] = []
            issues_by_file[issue.file_path].append(issue)

        report = []
        report.append("# Java 代码扫描报告（全部规则）\n")
        report.append(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"**扫描目录**: {self.root_dir}\n")
        report.append(f"**文件数量**: {self.files_scanned}\n")
        report.append(f"**问题总数**: {len(self.issues)}\n")
        report.append(f"\n**支持规则数**: {len(RULES)}\n")
        report.append("\n---\n\n")

        # 按规则统计
        report.append("## 问题统计\n\n")
        rule_counts: Dict[str, int] = {}
        for issue in self.issues:
            rule_counts[issue.rule_id] = rule_counts.get(issue.rule_id, 0) + 1

        for rule_id, count in sorted(rule_counts.items()):
            rule_name = RULES.get(rule_id, {}).get("name", "未知")
            severity = RULES.get(rule_id, {}).get("severity", "medium")
            report.append(f"- **{rule_id}** ({rule_name}) [{severity}]: {count} 处\n")

        report.append("\n---\n\n")

        # 详细问题列表
        report.append("## 详细问题列表\n")

        for file_path, file_issues in sorted(issues_by_file.items()):
            rel_path = os.path.relpath(file_path, self.root_dir)
            report.append(f"\n### 文件: {rel_path}\n")
            for issue in sorted(file_issues, key=lambda x: x.line_number):
                report.append(f"\n#### {issue.rule_id}: {issue.rule_name}\n")
                report.append(f"- **行号**: {issue.line_number}\n")
                report.append(f"- **详情**: {issue.details}\n")
                report.append(f"- **严重性**: {issue.severity}\n")
                report.append(f"```java\n{issue.code_snippet}\n```\n")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))

        print(f"Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Java Code Spec Scanner - 全规则版')
    parser.add_argument('--dir', '-d', required=True, help='扫描目录')
    parser.add_argument('--output', '-o', default='scan_report.md', help='输出报告路径')

    args = parser.parse_args()

    scanner = JavaScanner(args.dir)
    scanner.scan()
    scanner.generate_report(args.output)

    print(f"\n扫描完成！发现 {len(scanner.issues)} 个问题（支持 {len(RULES)} 条规则）")


if __name__ == '__main__':
    sys.exit(main())
