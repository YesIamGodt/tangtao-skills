#!/usr/bin/env python3
"""
Java Code Repair Learner - 自动学习闭环
1. 拉取新的Java项目
2. 运行扫描 + 修复
3. 验证修复效果
4. 记录学习经验
5. 持续优化规则
"""

import os
import sys
import json
import time
import random
import argparse
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False


# 推荐的Java开源项目列表（用于学习）
JAVA_PROJECTS = [
    # Apache项目
    ("apache/commons-lang", "Apache Commons Lang - Java基础工具库"),
    ("apache/commons-collections", "Apache Commons Collections"),
    ("apache/commons-io", "Apache Commons IO"),

    # 常用工具库
    ("google/guava", "Google Guava"),
    ("google/gson", "Google Gson"),
    ("alibaba/fastjson", "Alibaba FastJSON"),
    ("alibaba/druid", "Alibaba Druid数据库连接池"),

    # Spring生态
    ("spring-projects/spring-boot", "Spring Boot"),
    ("spring-projects/spring-framework", "Spring Framework"),

    # 国内项目
    ("dromara/hutool", "Hutool工具集"),
    ("dromara/MaxKey", "MaxKey认证中心"),
    ("SnailClimb/JavaGuide", "JavaGuide面试指南"),

    # 测试框架
    ("junit-team/junit5", "JUnit 5"),
    ("mockito/mockito", "Mockito测试框架"),
    ("testcontainers/testcontainers-java", "Testcontainers Java"),
]

# 规则优化配置
RULE_OPTIMIZATIONS = {
    "G.EXP.05": {
        "name": "空指针检查",
        "skip_patterns": [
            # 类名以大写开头的不检查
            lambda var: var[0].isupper() if var else False,
            # 静态工具类不检查
            "System", "Math", "Arrays", "Collections", "Objects",
            "StringUtils", "ClassUtils", "LoggerFactory",
            # Stream API不检查
            lambda var, line: "stream" in line.lower() or "lambda" in line.lower(),
        ],
        "require_context_check": True,  # 需要上下文分析
    },
    "G.PRM.07": {
        "name": "资源关闭",
        "resource_types": [
            "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
            "BufferedReader", "BufferedWriter", "InputStream", "OutputStream",
        ],
    },
}


@dataclass
class LearningResult:
    """学习结果"""
    project_name: str
    repo_url: str
    issues_found: int = 0
    issues_fixed: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    new_patterns_learned: int = 0
    execution_time: float = 0
    errors: List[str] = field(default_factory=list)
    learnings: List[str] = field(default_factory=list)


@dataclass
class FixEvaluation:
    """修复评估"""
    rule_id: str
    file_path: str
    line_number: int
    original_code: str
    fixed_code: str
    is_valid_fix: bool
    is_false_positive: bool
    notes: str = ""


class Learner:
    """自动学习器"""

    def __init__(self, repos_dir: str, learnings_dir: str):
        self.repos_dir = Path(repos_dir)
        self.learnings_dir = Path(learnings_dir)
        self.results: List[LearningResult] = []

        # 确保目录存在
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.learnings_dir.mkdir(parents=True, exist_ok=True)

    def clone_project(self, repo_url: str, project_name: str) -> Optional[str]:
        """克隆项目到本地"""
        target_dir = self.repos_dir / project_name.replace("/", "_")

        # 如果已存在，跳过克隆
        if target_dir.exists():
            print(f"  [SKIP] {project_name} already exists")
            return str(target_dir)

        print(f"  [CLONE] Cloning {project_name}...")

        if GIT_AVAILABLE:
            try:
                git.Repo.clone_from(repo_url, str(target_dir),
                                    depth=100,  # 浅克隆
                                    filter=['blob:none'])  # 不下载blob
                print(f"  [OK] Cloned to {target_dir}")
                return str(target_dir)
            except Exception as e:
                print(f"  [ERROR] Clone failed: {e}")
                return None
        else:
            # 使用git命令
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '100', repo_url, str(target_dir)],
                    check=True, capture_output=True
                )
                return str(target_dir)
            except subprocess.CalledProcessError as e:
                print(f"  [ERROR] Clone failed: {e}")
                return None

    def run_scanner(self, project_dir: str, output_report: str) -> bool:
        """运行扫描器"""
        scanner_path = os.path.join(os.path.dirname(__file__), "scanner.py")

        # 自动找到正确的 Java 源码目录
        scan_dir = self._find_java_source_dir(project_dir)
        if not scan_dir:
            print(f"  [ERROR] No Java source directory found in {project_dir}")
            return False

        print(f"  [SCAN] Scanning directory: {scan_dir}")

        try:
            result = subprocess.run(
                [sys.executable, scanner_path, '--dir', scan_dir, '--output', output_report],
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("  [ERROR] Scanner timeout")
            return False
        except Exception as e:
            print(f"  [ERROR] Scanner failed: {e}")
            return False

    def _find_java_source_dir(self, project_dir: str) -> Optional[str]:
        """自动找到 Java 源码目录"""
        # 常见的 Java 项目源码目录
        candidates = [
            os.path.join(project_dir, 'src', 'main', 'java'),
            os.path.join(project_dir, 'src'),  # 有些项目直接用 src
            os.path.join(project_dir, 'src', 'main'),  # 有些只有 main
            os.path.join(project_dir, 'src', 'java', 'main'),  # 有些奇怪的布局
        ]

        for candidate in candidates:
            if os.path.isdir(candidate):
                # 检查是否有 Java 文件
                for root, dirs, files in os.walk(candidate):
                    if any(f.endswith('.java') for f in files):
                        return candidate

        # 如果没找到，返回项目根目录（让扫描器自己决定）
        # 检查是否有任何 Java 文件
        for root, dirs, files in os.walk(project_dir):
            # 跳过特定目录
            if any(skip in root for skip in ['/.git/', '/target/', '/build/',
                                               '/.gradle/', '/node_modules/', '/test/']):
                continue
            if any(f.endswith('.java') for f in files):
                return project_dir

        return None

    def run_repair(self, project_dir: str, report_path: str,
                   scan_dir: str, preview: bool = True) -> Tuple[bool, str]:
        """运行修复器"""
        repair_path = os.path.join(os.path.dirname(__file__), "repair.py")

        try:
            cmd = [sys.executable, repair_path,
                   '--report', report_path,
                   '--repo', project_dir,
                   '--scan-dir', scan_dir]
            if preview:
                cmd.append('--preview')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # 解析输出获取修复数量
            output = result.stdout + result.stderr
            fixed_count = self._extract_fix_count(output)

            return result.returncode == 0, str(fixed_count)
        except subprocess.TimeoutExpired:
            return False, "0"
        except Exception as e:
            print(f"  [ERROR] Repair failed: {e}")
            return False, "0"

    def _extract_fix_count(self, output: str) -> int:
        """从输出中提取修复数量"""
        import re
        match = re.search(r'Issues fixed:\s*(\d+)', output)
        return int(match.group(1)) if match else 0

    def evaluate_fixes(self, project_dir: str) -> List[FixEvaluation]:
        """评估修复效果"""
        # TODO: 实现修复效果评估
        # 1. 检查修复后的代码是否能编译
        # 2. 运行测试
        # 3. 判断是否为误报
        return []

    def record_learning(self, result: LearningResult):
        """记录学习结果"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{result.project_name.replace('/', '_')}_{timestamp}.json"

        record_path = self.learnings_dir / filename

        with open(record_path, 'w', encoding='utf-8') as f:
            json.dump({
                "project_name": result.project_name,
                "repo_url": result.repo_url,
                "timestamp": datetime.now().isoformat(),
                "issues_found": result.issues_found,
                "issues_fixed": result.issues_fixed,
                "false_positives": result.false_positives,
                "false_negatives": result.false_negatives,
                "new_patterns_learned": result.new_patterns_learned,
                "execution_time": result.execution_time,
                "errors": result.errors,
                "learnings": result.learnings,
            }, f, indent=2, ensure_ascii=False)

        print(f"  [RECORD] Learning saved to {record_path}")

    def update_global_learnings(self):
        """更新全局学习记录"""
        learnings_file = self.learnings_dir / "learnings.json"

        all_learnings = []
        if learnings_file.exists():
            with open(learnings_file, 'r', encoding='utf-8') as f:
                all_learnings = json.load(f)

        # 合并新结果
        for result in self.results:
            entry = {
                "project": result.project_name,
                "date": datetime.now().isoformat(),
                "issues_found": result.issues_found,
                "issues_fixed": result.issues_fixed,
                "false_positives": result.false_positives,
                "learnings": result.learnings,
            }
            all_learnings.append(entry)

        # 保持最近100条
        all_learnings = all_learnings[-100:]

        with open(learnings_file, 'w', encoding='utf-8') as f:
            json.dump(all_learnings, f, indent=2, ensure_ascii=False)

    def learn_from_project(self, project: Tuple[str, str], preview: bool = True) -> LearningResult:
        """从单个项目学习"""
        repo_url, description = project
        project_name = repo_url.split("/")[-1]

        result = LearningResult(
            project_name=project_name,
            repo_url=f"https://github.com/{repo_url}.git"
        )

        print(f"\n{'='*60}")
        print(f"学习项目: {project_name}")
        print(f"描述: {description}")
        print(f"{'='*60}")

        start_time = time.time()

        try:
            # 1. 克隆项目
            project_dir = self.clone_project(result.repo_url, project_name)
            if not project_dir:
                result.errors.append("Clone failed")
                return result

            # 2. 运行扫描
            report_path = os.path.join(project_dir, "scan_report.md")
            print(f"\n[STEP 1] 运行扫描器...")
            if not self.run_scanner(project_dir, report_path):
                result.errors.append("Scanner failed")
                return result

            # 读取扫描结果
            with open(report_path, 'r', encoding='utf-8') as f:
                content = f.read()
                import re
                matches = re.findall(r'#### (G\.\w+):', content)
                result.issues_found = len(matches)

            print(f"  发现 {result.issues_found} 个问题")

            # 3. 运行修复
            scan_dir = self._find_java_source_dir(project_dir)
            print(f"\n[STEP 2] 运行修复器 (preview={preview})...")
            success, fix_count = self.run_repair(project_dir, report_path, scan_dir, preview)
            result.issues_fixed = int(fix_count) if fix_count.isdigit() else 0

            if success:
                print(f"  修复了 {result.issues_fixed} 个问题")
            else:
                result.errors.append("Repair failed")

            # 4. 评估修复效果
            print(f"\n[STEP 3] 评估修复效果...")
            evaluations = self.evaluate_fixes(project_dir)

            # 5. 记录学习
            print(f"\n[STEP 4] 记录学习...")
            result.learnings.append(f"项目 {project_name} 完成扫描修复")

            # 估算误报率
            if result.issues_found > 0:
                estimated_fp = max(0, result.issues_found - result.issues_fixed)
                result.false_positives = estimated_fp

        except Exception as e:
            result.errors.append(str(e))
            print(f"  [ERROR] {e}")

        result.execution_time = time.time() - start_time

        # 记录结果
        self.record_learning(result)

        return result

    def run_learning_cycle(self, projects: List[Tuple[str, str]] = None,
                          count: int = 3, preview: bool = True,
                          random_order: bool = True):
        """运行学习循环"""
        if projects is None:
            projects = JAVA_PROJECTS

        # 随机选择项目
        if random_order:
            selected = random.sample(projects, min(count, len(projects)))
        else:
            selected = projects[:count]

        print(f"\n开始学习循环")
        print(f"项目数量: {len(selected)}")
        print(f"预览模式: {preview}")
        print(f"随机顺序: {random_order}")

        total_results = []

        for i, project in enumerate(selected, 1):
            print(f"\n[{i}/{len(selected)}] ", end="")

            result = self.learn_from_project(project, preview=preview)
            total_results.append(result)
            self.results.extend(total_results)

            # 短暂休息，避免过快
            if i < len(selected):
                time.sleep(2)

        # 更新全局学习记录
        self.update_global_learnings()

        # 打印总结
        self.print_summary(total_results)

    def print_summary(self, results: List[LearningResult]):
        """打印学习总结"""
        print(f"\n{'='*60}")
        print("学习循环总结")
        print(f"{'='*60}")

        total_projects = len(results)
        total_issues = sum(r.issues_found for r in results)
        total_fixed = sum(r.issues_fixed for r in results)
        total_fp = sum(r.false_positives for r in results)
        total_time = sum(r.execution_time for r in results)

        print(f"处理项目: {total_projects}")
        print(f"发现问题: {total_issues}")
        print(f"修复问题: {total_fixed}")
        print(f"误报数量: {total_fp}")

        if total_issues > 0:
            accuracy = (total_fixed / total_issues) * 100
            print(f"修复准确率: {accuracy:.1f}%")

        print(f"总耗时: {total_time:.1f}s")

        # 显示详细结果
        print(f"\n详细结果:")
        for r in results:
            status = "OK" if not r.errors else "ERROR"
            print(f"  [{status}] {r.project_name}: "
                  f"{r.issues_fixed}/{r.issues_found} 修复, "
                  f"{r.false_positives} 误报")


def main():
    parser = argparse.ArgumentParser(description='Java Code Repair Learner')
    parser.add_argument('--repos-dir', '-r', default='./repos',
                       help='仓库存储目录')
    parser.add_argument('--learnings-dir', '-l', default='./learnings',
                       help='学习记录目录')
    parser.add_argument('--count', '-n', type=int, default=3,
                       help='学习的项目数量')
    parser.add_argument('--preview', action='store_true', default=True,
                       help='预览模式（不实际修改）')
    parser.add_argument('--no-preview', dest='preview', action='store_false',
                       help='实际执行修复')
    parser.add_argument('--random', action='store_true', default=True,
                       help='随机选择项目')
    parser.add_argument('--sequential', dest='random', action='store_false',
                       help='按顺序选择项目')
    parser.add_argument('--projects', '-p', nargs='+',
                       help='指定项目列表 (owner/repo)')

    args = parser.parse_args()

    # 确定项目列表
    if args.projects:
        projects = [(p, "") for p in args.projects]
    else:
        projects = JAVA_PROJECTS

    # 创建学习器
    learner = Learner(args.repos_dir, args.learnings_dir)

    # 运行学习
    learner.run_learning_cycle(
        projects=projects,
        count=args.count,
        preview=args.preview,
        random_order=args.random
    )


if __name__ == '__main__':
    sys.exit(main())
