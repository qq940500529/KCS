# KCS 开发环境搭建指南

## 1. 系统要求

### 1.1 硬件要求

**生产环境**：
- 服务器必须配备 TPM 2.0 芯片
- 推荐：4 核 CPU，8GB RAM，50GB 磁盘空间

**开发环境**：
- 任何现代计算机（将使用 TPM 模拟器）
- 推荐：2 核 CPU，4GB RAM，20GB 磁盘空间

### 1.2 软件要求

- **操作系统**：Ubuntu 20.04+ / CentOS 8+ / macOS 11+
- **Python**：3.8+（后端开发）
- **Node.js**：16+（前端开发）
- **Git**：2.0+
- **Docker**：20.10+（可选，用于容器化）

## 2. 后端开发环境搭建

### 2.1 安装系统依赖

#### Ubuntu/Debian

```bash
# 更新包管理器
sudo apt-get update

# 安装基础开发工具
sudo apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    vim

# 安装 TPM 工具栈
sudo apt-get install -y \
    tpm2-tools \
    tpm2-abrmd \
    libtpm2-pkcs11-1 \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtpms-dev \
    swtpm \
    swtpm-tools

# 安装 Python 开发环境
sudo apt-get install -y \
    python3.8 \
    python3-pip \
    python3-venv
```

#### macOS

```bash
# 安装 Homebrew（如果未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装依赖
brew install python@3.9 tpm2-tools swtpm git
```

### 2.2 克隆项目

```bash
# 克隆仓库
git clone https://github.com/qq940500529/KCS.git
cd KCS
```

### 2.3 设置 Python 虚拟环境

```bash
# 创建虚拟环境
cd backend
python3 -m venv venv

# 激活虚拟环境
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# 升级 pip
pip install --upgrade pip
```

### 2.4 安装 Python 依赖

```bash
# 安装核心依赖（需要先创建 requirements.txt）
pip install -r requirements.txt

# 如果 requirements.txt 不存在，手动安装核心包
pip install \
    flask \
    flask-cors \
    tpm2-pytss \
    cryptography \
    pydantic \
    python-dotenv \
    requests
```

### 2.5 配置 TPM 模拟器（开发环境）

```bash
# 创建 TPM 状态目录
mkdir -p /tmp/kcs_tpm_state

# 启动 swtpm 模拟器
swtpm socket \
    --tpmstate dir=/tmp/kcs_tpm_state \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --tpm2 \
    --flags not-need-init &

# 设置环境变量
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

# 验证 TPM 可用
tpm2_getcap properties-fixed
```

### 2.6 创建配置文件

```bash
# 创建 .env 文件
cd backend
cat > .env << EOF
# 服务器配置
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
SERVER_URL=https://localhost:5000

# TPM 配置
TPM_ENABLED=true
TPM_SIMULATOR=true
TPM_TCTI=swtpm:host=localhost,port=2321

# 核心密钥配置
CORE_KEY_LABEL=kcs-core-key-v1
CORE_KEY_HANDLE=0x81010001

# 日志配置
LOG_LEVEL=DEBUG
LOG_FILE=logs/kcs.log

# 安全配置
SECRET_KEY=your-secret-key-change-in-production
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5000

# 时间配置
TIMEZONE=UTC
EOF
```

### 2.7 初始化数据库（如果需要）

```bash
# 创建必要的目录
mkdir -p backend/logs
mkdir -p backend/data

# 运行初始化脚本（待开发）
# python src/init_db.py
```

### 2.8 运行后端服务

```bash
# 开发模式运行
cd backend
python src/main.py

# 或使用 Flask 命令
export FLASK_APP=src/main.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000
```

## 3. 前端开发环境搭建

### 3.1 安装 Node.js 和 npm

#### Ubuntu/Debian

```bash
# 使用 NodeSource 仓库安装最新 Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 验证安装
node --version
npm --version
```

#### macOS

```bash
# 使用 Homebrew 安装
brew install node

# 验证安装
node --version
npm --version
```

### 3.2 安装前端依赖

```bash
cd frontend

# 初始化项目（如果 package.json 不存在）
npm init -y

# 安装核心依赖（React 示例）
npm install react react-dom react-router-dom
npm install axios
npm install @mui/material @emotion/react @emotion/styled
npm install date-fns

# 安装开发依赖
npm install --save-dev \
    @vitejs/plugin-react \
    vite \
    eslint \
    prettier
```

### 3.3 创建前端配置

```bash
# 创建 .env 文件
cd frontend
cat > .env << EOF
# API 配置
VITE_API_BASE_URL=http://localhost:5000/api/v1
VITE_API_TIMEOUT=30000

# 应用配置
VITE_APP_NAME=KCS
VITE_APP_VERSION=1.0.0
EOF
```

### 3.4 运行前端服务

```bash
cd frontend

# 开发模式运行
npm run dev

# 或使用 Vite
npx vite
```

## 4. Docker 开发环境（推荐）

### 4.1 创建 Dockerfile

#### 后端 Dockerfile

```dockerfile
# backend/Dockerfile
FROM python:3.9-slim

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    tpm2-tools \
    libtss2-dev \
    swtpm \
    swtpm-tools \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 暴露端口
EXPOSE 5000

# 启动命令
CMD ["python", "src/main.py"]
```

#### 前端 Dockerfile

```dockerfile
# frontend/Dockerfile
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY package*.json ./

# 安装依赖
RUN npm ci

# 复制应用代码
COPY . .

# 暴露端口
EXPOSE 3000

# 启动命令
CMD ["npm", "run", "dev"]
```

### 4.2 创建 Docker Compose 配置

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "5000:5000"
    environment:
      - TPM_SIMULATOR=true
      - TPM_TCTI=swtpm:host=tpm-simulator,port=2321
      - SERVER_URL=http://localhost:5000
    volumes:
      - ./backend:/app
      - /tmp/kcs_tpm_state:/tmp/tpm_state
    depends_on:
      - tpm-simulator
    networks:
      - kcs-network

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - VITE_API_BASE_URL=http://localhost:5000/api/v1
    volumes:
      - ./frontend:/app
      - /app/node_modules
    depends_on:
      - backend
    networks:
      - kcs-network

  tpm-simulator:
    image: stefanberger/swtpm:latest
    command: |
      sh -c "mkdir -p /tmp/tpm_state && 
             swtpm socket --tpmstate dir=/tmp/tpm_state 
             --ctrl type=tcp,port=2322 
             --server type=tcp,port=2321 
             --tpm2 
             --flags not-need-init"
    ports:
      - "2321:2321"
      - "2322:2322"
    volumes:
      - /tmp/kcs_tpm_state:/tmp/tpm_state
    networks:
      - kcs-network

networks:
  kcs-network:
    driver: bridge
```

### 4.3 使用 Docker Compose

```bash
# 构建并启动所有服务
docker-compose up --build

# 后台运行
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 停止并删除卷
docker-compose down -v
```

## 5. 开发工具配置

### 5.1 VSCode 配置

创建 `.vscode/settings.json`：

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/backend/venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": true,
  "python.formatting.provider": "black",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  },
  "[python]": {
    "editor.tabSize": 4
  },
  "[javascript]": {
    "editor.tabSize": 2
  },
  "[typescript]": {
    "editor.tabSize": 2
  }
}
```

### 5.2 推荐的 VSCode 扩展

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "ms-azuretools.vscode-docker",
    "eamodio.gitlens"
  ]
}
```

### 5.3 Git Hooks（可选）

```bash
# 安装 pre-commit
pip install pre-commit

# 创建 .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
EOF

# 安装 hooks
pre-commit install
```

## 6. 验证开发环境

### 6.1 验证后端

```bash
cd backend

# 激活虚拟环境
source venv/bin/activate

# 运行测试（需要先创建测试）
# pytest tests/

# 检查 TPM 连接
python -c "from tpm2_pytss import ESAPI; print('TPM OK')"

# 启动开发服务器
python src/main.py
```

访问 `http://localhost:5000/health` 应该看到服务状态。

### 6.2 验证前端

```bash
cd frontend

# 运行开发服务器
npm run dev
```

访问 `http://localhost:3000` 应该看到前端界面。

### 6.3 端到端测试

1. 打开浏览器访问 `http://localhost:3000`
2. 尝试生成密钥
3. 尝试转换密钥
4. 检查控制台是否有错误

## 7. 常见问题

### 7.1 TPM 模拟器无法启动

```bash
# 检查端口是否被占用
lsof -i :2321
lsof -i :2322

# 杀死占用进程
kill -9 <PID>

# 清理 TPM 状态
rm -rf /tmp/kcs_tpm_state/*
```

### 7.2 Python 包安装失败

```bash
# 升级 pip
pip install --upgrade pip setuptools wheel

# 使用国内镜像源
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple <package>
```

### 7.3 前端依赖安装失败

```bash
# 清理缓存
npm cache clean --force

# 删除 node_modules
rm -rf node_modules package-lock.json

# 重新安装
npm install
```

### 7.4 CORS 错误

确保后端配置了正确的 CORS 设置：

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])
```

## 8. 下一步

开发环境搭建完成后，您可以：

1. 阅读 [架构文档](../architecture/ARCHITECTURE.md)
2. 查看 [API 文档](../api/API.md)
3. 学习 [TPM 集成指南](TPM_INTEGRATION.md)
4. 开始编写代码！

## 9. 获取帮助

- 查看 [GitHub Issues](https://github.com/qq940500529/KCS/issues)
- 阅读 [贡献指南](../../CONTRIBUTING.md)
- 联系维护者

## 10. 生产环境部署准备

开发完成后，参考 [部署文档](../deployment/DEPLOYMENT.md) 了解如何将系统部署到生产环境。
