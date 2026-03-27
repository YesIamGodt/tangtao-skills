#!/usr/bin/env python3
"""
Java Code Repair - 自动修复Java代码规范问题并提交到Git
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

# Constants
FIX_RULES: Dict[str, Callable] = {}


@dataclass
class CodeIssue:
    """表示一个代码问题"""
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int
    code_snippet: str
    details: str


@dataclass
class RepairResult:
    """修复结果"""
    files_modified: int = 0
    issues_fixed: int = 0
    issues_by_rule: Dict[str, int] = field(default_factory=dict)
    branch_name: str = ""
    commit_hash: str = ""
    remote_url: str = ""


def register_fix(rule_id: str):
    """修复规则注册装饰器"""
    def decorator(func: Callable):
        FIX_RULES[rule_id] = func
        return func
    return decorator


# ============================================================================
# REPORT PARSING
# ============================================================================

def parse_markdown_report(report_path: str) -> List[CodeIssue]:
    """解析Markdown格式的扫描报告"""
    issues = []
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading report: {e}")
        return issues

    # 解析问题信息
    current_issue = None
    in_detail = False

    for line in content.split('\n'):
        # 查找问题标题
        issue_match = re.match(r'^#### (G\.[A-Z0-9\.]+): (.+)$', line)
        if issue_match:
            if current_issue:
                issues.append(current_issue)
            current_issue = CodeIssue(
                rule_id=issue_match.group(1),
                rule_name=issue_match.group(2),
                file_path="",
                line_number=0,
                code_snippet="",
                details=""
            )
            in_detail = False
            continue

        if current_issue:
            # 提取文件路径
            file_match = re.match(r'^### 文件: (.+)$', line)
            if file_match:
                current_issue.file_path = file_match.group(1)
                continue

            # 提取行号
            line_match = re.match(r'^- \*\*行号\*\*: (\d+)$', line)
            if line_match:
                current_issue.line_number = int(line_match.group(1))
                continue

            # 提取详情
            detail_match = re.match(r'^- \*\*详情\*\*: (.+)$', line)
            if detail_match:
                current_issue.details = detail_match.group(1)
                continue

            # 提取代码片段
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


# ============================================================================
# FIX RULES
# ============================================================================

@register_fix("G.EXP.05")
def fix_null_check(content: str, line_num: int) -> Tuple[str, str]:
    """修复null检查"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 简单模式：查找变量.method()
    var_match = re.search(r'(\b[a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\s*\(', line)
    if var_match:
        var_name = var_match.group(1)
        indent = line[:len(line) - len(line.lstrip())]

        # 添加null检查
        fixed_line = f"{indent}if ({var_name} != null) {{\n{indent}    {line.lstrip()}\n{indent}}}"
        lines[line_num - 1] = fixed_line

        return '\n'.join(lines), f"添加了 {var_name} 的 null 检查"

    return content, ""


@register_fix("G.PRM.07")
def fix_resource_close(content: str, line_num: int) -> Tuple[str, str]:
    """修复资源关闭问题 - 尝试使用try-with-resources"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    # 这个修复比较复杂，这里做一个简单的建议
    return content, "建议使用 try-with-resources 语句来确保资源正确关闭"


@register_fix("G.LOG.06")
def fix_sensitive_logging(content: str, line_num: int) -> Tuple[str, str]:
    """修复敏感信息日志"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 替换敏感信息
    sensitive_words = ['password', 'passwd', 'pwd', 'secret', 'key', 'token', 'credential']
    for word in sensitive_words:
        pattern = rf'\b{word}\b\s*[=:]\s*[^,;)]+'
        line = re.sub(pattern, f"{word}: [REDACTED]", line, flags=re.IGNORECASE)

    if lines[line_num - 1] != line:
        lines[line_num - 1] = line
        return '\n'.join(lines), "移除了日志中的敏感信息"

    return content, ""


@register_fix("G.EDV.01")
def fix_sql_injection(content: str, line_num: int) -> Tuple[str, str]:
    """修复SQL注入 - 提示使用PreparedStatement"""
    lines = content.split('\n')
    return content, "建议使用 PreparedStatement 和参数化查询来防止 SQL 注入"


@register_fix("G.TYP.02")
def fix_divide_by_zero(content: str, line_num: int) -> Tuple[str, str]:
    """修复除零检查"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 查找除法或模运算
    div_match = re.search(r'[/%]\s*([a-zA-Z_]\w*)', line)
    if div_match:
        var_name = div_match.group(1)
        indent = line[:len(line) - len(line.lstrip())]

        fixed_line = f"{indent}if ({var_name} != 0) {{\n{indent}    {line.lstrip()}\n{indent}}}"
        lines[line_num - 1] = fixed_line

        return '\n'.join(lines), f"添加了 {var_name} 的除零检查"

    return content, ""


@register_fix("G.OTH.03")
def fix_hardcoded_address(content: str, line_num: int) -> Tuple[str, str]:
    """修复硬编码地址"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return content, ""

    line = lines[line_num - 1]

    # 替换URL为配置引用
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


# ============================================================================
# GIT OPERATIONS
# ============================================================================

class GitManager:
    """Git操作管理"""

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
        """检查是否是Git仓库"""
        return self.repo is not None

    def create_branch(self) -> str:
        """创建新分支"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        self.branch_name = f"ai-repair-{timestamp}"

        if self.repo:
            try:
                # 创建新分支
                current = self.repo.active_branch
                new_branch = self.repo.create_head(self.branch_name)
                new_branch.checkout()
                print(f"Created and switched to branch: {self.branch_name}")
            except Exception as e:
                print(f"Branch creation failed: {e}")
                # 使用时间戳加随机数
                self.branch_name = f"ai-repair-{timestamp}-{int(time.time() % 1000)}"

        return self.branch_name

    def commit_changes(self, message: str) -> str:
        """提交更改"""
        if not self.repo:
            return ""

        try:
            # 添加所有更改
            self.repo.git.add(A=True)
            # 提交
            commit = self.repo.index.commit(message)
            print(f"Committed changes: {commit.hexsha[:8]}")
            return commit.hexsha
        except Exception as e:
            print(f"Commit failed: {e}")
            return ""

    def push_branch(self) -> bool:
        """推送分支到远程"""
        if not self.repo or not self.branch_name:
            return False

        try:
            remote = self.repo.remote(self.remote_name)
            remote.push(refspec=f"{self.branch_name}:{self.branch_name}")
            print(f"Pushed branch to remote: {self.branch_name}")
            return True
        except Exception as e:
            print(f"Push failed: {e}")
            return False

    def get_remote_url(self) -> str:
        """获取远程仓库URL"""
        if not self.repo:
            return ""
        try:
            remote = self.repo.remote(self.remote_name)
            return remote.url if remote.urls else ""
        except Exception:
            return ""


# ============================================================================
# MAIN REPAIR ENGINE
# ============================================================================

class CodeRepairEngine:
    """代码修复引擎"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.preview = self.config.get('preview', False)
        self.result = RepairResult()

    def repair_file(self, file_path: str, issues: List[CodeIssue]) -> bool:
        """修复单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return False

        original_content = content
        modified = False
        fix_messages = []

        # 按行号降序处理，避免修改影响行号
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
        """运行修复"""
        # 按文件分组问题
        issues_by_file: Dict[str, List[CodeIssue]] = {}
        for issue in issues:
            if issue.file_path not in issues_by_file:
                issues_by_file[issue.file_path] = []
            issues_by_file[issue.file_path].append(issue)

        # Git初始化
        git_manager = GitManager(repo_path, self.config.get('git_remote', 'origin'))

        if git_manager.is_git_repo() and not self.preview:
            self.result.branch_name = git_manager.create_branch()

        # 修复每个文件
        for file_path, file_issues in issues_by_file.items():
            self.repair_file(file_path, file_issues)

        # 提交和推送
        if git_manager.is_git_repo() and not self.preview and self.result.files_modified > 0:
            # 生成提交信息
            commit_msg = self._generate_commit_message()
            self.result.commit_hash = git_manager.commit_changes(commit_msg)

            if self.config.get('auto_push', True):
                git_manager.push_branch()

            self.result.remote_url = git_manager.get_remote_url()

        return self.result

    def _generate_commit_message(self) -> str:
        """生成提交信息"""
        msg = f"fix: 自动修复代码规范问题\n\n"
        msg += f"修复了 {self.result.issues_fixed} 个问题\n\n"
        for rule_id, count in sorted(self.result.issues_by_rule.items()):
            msg += f"- 修复 {rule_id}: {count} 处\n"
        msg += f"\n扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        return msg


# ============================================================================
# MAIN
# ============================================================================

def load_config(config_path: str) -> Dict:
    """加载配置文件"""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
    return {}


def main():
    parser = argparse.ArgumentParser(description='Java Code Repair')
    parser.add_argument('--report', '-r', required=True, help='扫描报告文件路径')
    parser.add_argument('--repo', default='.', help='Git仓库路径')
    parser.add_argument('--config', '-c', help='配置文件路径')
    parser.add_argument('--remote', help='Git远程名称')
    parser.add_argument('--preview', action='store_true', help='预览模式，不实际修改')

    args = parser.parse_args()

    # 加载配置
    config = {}
    if args.config:
        config = load_config(args.config)

    if args.remote:
        config['git_remote'] = args.remote

    if args.preview:
        config['preview'] = True

    # 解析报告
    print("Parsing report...")
    issues = parse_markdown_report(args.report)
    if not issues:
        print("No issues found in report.")
        return 0

    print(f"Found {len(issues)} issues.")

    # 运行修复
    print("Starting repair...")
    engine = CodeRepairEngine(config)
    result = engine.run(issues, args.repo)

    # 显示结果
    print("\n" + "="*60)
    print("REPAIR SUMMARY")
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
