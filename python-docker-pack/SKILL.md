---
name: python-docker-pack
description: >
  将 Python 代码仓库自动构建为 Docker 镜像并导出为 tar 包。当用户提到以下场景时触发：
  - 用户说"帮我把这个 Python 项目打包成 docker 镜像"或类似表达
  - 用户说"把 Python 代码打成 docker tar"或"docker build Python 项目"
  - 用户指定一个 Python 代码目录，希望生成 Dockerfile 并打包
  - 用户提到 Flask/Django/FastAPI 项目需要 Docker 化
  - 用户提到 pip/poetry/pdm/uv 等 Python 包管理工具需要 Docker 化
  只要涉及 Python 项目的 Docker 打包，就是这个 skill 的适用范围。
---

# Python Docker Pack Skill

将 Python 代码仓库自动构建为 Docker 镜像，并导出为 `.tar`（或 `.tar.gz`）文件，专注于 Python 生态的最佳实践。

## 工作流程

```
第1步：分析代码仓库
第2步：确认打包需求（主动向用户提问）
第3步：生成 Dockerfile
第4步：构建镜像
第5步：docker save 导出 tar
第6步：输出结果汇总
```

---

## 第1步：分析代码仓库

在项目根目录执行以下检查：

1. **判断语言/框架**：检查是否已有 Dockerfile（已有则问用户是否复用）
2. **检测 Python 包管理工具**：
   - `requirements.txt` → pip
   - `pyproject.toml` + `poetry.lock` → Poetry
   - `pyproject.toml` + `pdm.lock` → PDM
   - `uv.lock` → uv
   - `Pipfile` + `Pipfile.lock` → Pipenv
3. **检测 Web 框架**：Flask / Django / FastAPI / Streamlit / Gradio 等（影响基础镜像和启动命令）
4. **检测 Python 版本**：`.python-version` / `pyproject.toml` 中的 python 版本
5. **检测构建产物**：`dist/` / `build/` / `*.whl` 等
6. **检查 .dockerignore**：是否存在，缺失则建议创建
7. **列出项目结构**：`ls` 或 `find` 了解整体结构

完成后汇报：**这是什么类型的 Python 项目？使用什么包管理器？有哪些文件/目录需要打包？有没有特殊依赖？**

---

## 第2步：确认打包需求

向用户提问（或根据已有信息推断），收集以下信息：

### 必须确认（Missing 时必须问）

| 问题 | 选项/说明 |
|------|----------|
| Python 版本？ | 3.9 / 3.10 / 3.11 / 3.12 等，或让 AI 推荐（建议用较新稳定版） |
| 基础镜像？ | `python:3.12-slim` / `python:3.12-alpine` / `python:3.12-bookworm` 等 |
| 工作目录 WORKDIR？ | 默认 `/app` |
| 启动命令 CMD/ENTRYPOINT？ | 必须有，例如 `python main.py`、`uvicorn app:app` |
| 包管理工具？ | pip / poetry / pdm / uv / pipenv |

### 可选优化（没有时给出建议）

- 是否需要多阶段构建（减小镜像体积）？
- 是否需要预装系统依赖（如 `libpq-dev` 用于 psycopg2）？
- 镜像 tag 叫什么名字？
- 输出文件名叫什么？（默认 `{项目名}_{tag}.tar.gz`）

> **主动推荐原则**：如果用户没有明确指定，给出推荐值并说明原因，等用户确认或修改。
> **不过度提问**：能根据代码推断的（如 Python 版本从 pyproject.toml 推断），就不要问。

---

## 第3步：生成 Dockerfile

根据上一步的信息，生成 `Dockerfile`。

### 包管理器的 Dockerfile 策略

#### pip + requirements.txt（最常见）
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

#### Poetry
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml poetry.lock* ./
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi
COPY . .
CMD ["python", "main.py"]
```

#### PDM
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml pdm.lock* ./
RUN pip install pdm && pdm install --prod --no-interaction
COPY . .
CMD ["python", "main.py"]
```

#### uv（最快）
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY uv.lock pyproject.toml ./
RUN pip install uv && uv sync --frozen --prod
COPY . .
CMD ["python", "main.py"]
```

### 生成原则

- **多阶段构建优先**：先安装依赖，再 copy 产物，最后运行
- **使用 slim/alpine 镜像**：减小体积，如 `python:3.12-slim` 而非 `python:3.12`
- **显式 Python 版本**：基础镜像带版本标签
- **--no-cache-dir**：pip 安装时加上，减少镜像体积
- **COPY 顺序优化**：先复制依赖文件（不变），再复制源码（经常变），充分利用 Docker 缓存
- **用户目录优先**：COPY 时排除 `.git` `__pycache__` `.pytest_cache` `*.pyc` `.venv` 等

### Web 框架的启动命令参考

| 框架 | 启动命令示例 |
|------|------------|
| FastAPI/Uvicorn | `uvicorn main:app --host 0.0.0.0 --port 8000` |
| Flask | `flask run --host 0.0.0.0`（需设置 FLASK_APP） |
| Django | `python manage.py runserver 0.0.0.0:8000` |
| Streamlit | `streamlit run app.py --server.port 8501` |
| Gradio | `python app.py` |
| 脚本项目 | `python main.py` 或 `python -m module` |

生成后把 Dockerfile 内容展示给用户，说明关键决策（为什么选这个基础镜像、为什么用这个包管理策略），等用户确认后再继续。

---

## 第4步：构建镜像

```bash
docker build -t <image-name>:<tag> <context-path>
```

- `context-path` 始终为项目根目录
- 构建成功后显示镜像大小：`docker images <image-name>`
- 构建失败时，分析错误信息，给出修复建议

---

## 第5步：导出 tar

```bash
# 导出为 tar.gz（推荐）
docker save <image-name>:<tag> | gzip > <output>.tar.gz

# 或只导出 tar
docker save <image-name>:<tag> -o <output>.tar
```

---

## 第6步：输出结果汇总

完成后向用户汇报：
- 镜像名称和 tag
- 镜像大小
- tar 包路径和大小
- 如何加载回 Docker：`docker load -i <output>.tar.gz`

---

## 常见 Python 依赖的 Docker 注意事项

| 依赖类型 | 注意事项 |
|---------|---------|
| `psycopg2`（PostgreSQL） | 需要系统依赖 `libpq-dev`，在 RUN pip install 前添加 `apt-get install` |
| `mysqlclient`（MySQL） | 需要 `libmysqlclient-dev pkg-config python3-dev build-essential` |
| `Pillow`（PIL） | 需要 `libjpeg-dev zlib1g-dev libpng-dev` |
| `cryptography` | 需要 `libffi-dev build-essential` |
| `uvicorn` + `fastapi` | 直接 `pip install` 即可，无需额外系统依赖 |
| `numpy / pandas` | 使用 `python:3.12-slim` 即可，alpine 可能有兼容性问题 |

如果检测到这些依赖，在 Dockerfile 中自动添加对应的 `apt-get install` 步骤。

---

## .dockerignore 推荐内容（Python 项目）

```
__pycache__
*.pyc
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info
dist
build
.pytest_cache
.coverage
htmlcov
.venv
venv
ENV
env
.git
.gitignore
.dockerignore
*.md
Dockerfile
.dockerignore
.env
.env.local
```

---

## 遇到问题怎么办

| 问题类型 | 处理方式 |
|---------|---------|
| 没有找到 Python 相关文件 | 说明这不是 Python 项目，建议使用 docker-pack 通用 skill |
| 包管理器不确定 | 问用户：是 `pip install` / `poetry install` / `uv sync` / 其他？ |
| 基础镜像不确定 | 给出推荐（如 Python 3.12 + slim）并附上理由 |
| 系统依赖不确定 | 检测 import 语句，推断需要的系统依赖 |
| docker not found | 提示用户安装 Docker Desktop |
| 构建失败 | 分析具体错误（权限、依赖缺失、语法错误），给出修复建议 |
| Poetry/PDM 安装慢 | 建议改用 pip 或 uv，或在多阶段构建中用缓存层 |
| 用户需求不明确 | 用自然语言提问："你的项目是用什么方式管理依赖的？有 requirements.txt 吗？" |

---

## 交互风格要求

- **主动汇报进度**：每完成一步，简单告诉用户当前状态
- **不过度汇报**：不要事无巨细，重点说明决策和结果
- **给出建议而非选项**：尽量给出最优推荐值
- **Python 特色**：用 Python 开发者熟悉的术语，多给出"最佳实践"而非强制规范
