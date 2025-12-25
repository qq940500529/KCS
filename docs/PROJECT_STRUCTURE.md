# KCS 项目结构

本文档描述了 KCS (Key Conversion System) 项目的完整文件夹结构。

## 项目根目录

```
KCS/
├── .git/                   # Git 版本控制
├── .github/                # GitHub 配置
│   └── workflows/          # GitHub Actions CI/CD
├── backend/                # 后端服务
│   ├── src/                # 源代码
│   │   ├── api/            # API 接口层
│   │   ├── crypto/         # 加密算法模块
│   │   ├── models/         # 数据模型
│   │   ├── tpm/            # TPM 交互模块
│   │   └── utils/          # 工具函数
│   ├── tests/              # 后端测试
│   ├── config/             # 配置文件
│   ├── requirements.txt    # Python 依赖
│   └── README.md           # 后端说明
├── frontend/               # 前端应用
│   ├── src/                # 源代码
│   │   ├── components/     # React 组件
│   │   ├── pages/          # 页面组件
│   │   ├── services/       # API 服务
│   │   └── utils/          # 工具函数
│   ├── public/             # 静态资源
│   ├── tests/              # 前端测试
│   ├── package.json        # npm 依赖
│   └── README.md           # 前端说明
├── docs/                   # 项目文档
│   ├── api/                # API 文档
│   │   └── API.md          # API 接口文档
│   ├── architecture/       # 架构文档
│   │   ├── ARCHITECTURE.md # 系统架构
│   │   └── SECURITY.md     # 安全设计
│   ├── guides/             # 开发指南
│   │   ├── DEVELOPMENT_SETUP.md  # 环境搭建
│   │   └── TPM_INTEGRATION.md    # TPM 集成
│   └── deployment/         # 部署文档
│       └── DEPLOYMENT.md   # 部署指南
├── tests/                  # 集成测试
│   ├── unit/               # 单元测试
│   ├── integration/        # 集成测试
│   └── e2e/                # 端到端测试
├── scripts/                # 脚本工具
├── .gitignore              # Git 忽略文件
├── CONTRIBUTING.md         # 贡献指南
└── README.md               # 项目说明
```

## 目录说明

### `/backend` - 后端服务

后端使用 Python + Flask/FastAPI 开发，负责：
- TPM 交互
- 密钥生成和转换逻辑
- API 接口提供
- 安全验证

**关键子目录**：
- `src/api/`: REST API 接口定义
- `src/tpm/`: TPM 2.0 硬件交互
- `src/crypto/`: 加密算法实现
- `src/models/`: 数据模型定义
- `tests/`: 单元测试和集成测试

### `/frontend` - 前端应用

前端使用 React + TypeScript 开发，提供：
- 密钥生成界面
- 密钥转换界面
- 用户交互和验证

**关键子目录**：
- `src/components/`: 可复用的 React 组件
- `src/pages/`: 页面级组件
- `src/services/`: API 调用封装
- `public/`: 静态资源（图标、图片等）

### `/docs` - 文档

完整的项目文档，包括：
- **API 文档**: 接口定义、参数说明、示例
- **架构文档**: 系统设计、模块划分、数据流
- **开发指南**: 环境搭建、编码规范、TPM 集成
- **部署文档**: 生产环境部署、配置说明

### `/tests` - 测试

项目级别的测试：
- `unit/`: 单元测试
- `integration/`: 集成测试（跨模块）
- `e2e/`: 端到端测试（完整流程）

### `/scripts` - 脚本工具

辅助脚本：
- 数据库初始化
- 部署脚本
- 开发工具
- CI/CD 脚本

### `/.github` - GitHub 配置

- `workflows/`: GitHub Actions 工作流
  - CI/CD 流程
  - 自动化测试
  - 代码质量检查

## 文件命名约定

### Python 文件
- 模块文件：`snake_case.py`
- 测试文件：`test_*.py` 或 `*_test.py`
- 配置文件：`config.py` 或 `settings.py`

### JavaScript/TypeScript 文件
- 组件文件：`PascalCase.tsx`
- 工具文件：`camelCase.ts`
- 测试文件：`*.test.ts` 或 `*.spec.ts`
- 配置文件：`*.config.ts`

### 文档文件
- Markdown 文件：`UPPERCASE.md` (重要文档) 或 `Title_Case.md`
- 一般约定：使用描述性名称，如 `API.md`, `DEPLOYMENT.md`

## 配置文件位置

- **后端配置**: `backend/.env`, `backend/config/`
- **前端配置**: `frontend/.env`, `frontend/vite.config.ts`
- **Git 配置**: `.gitignore`
- **Docker 配置**: `Dockerfile`, `docker-compose.yml`
- **CI/CD 配置**: `.github/workflows/`

## 开始开发

1. **克隆仓库**
   ```bash
   git clone https://github.com/qq940500529/KCS.git
   cd KCS
   ```

2. **查看文档**
   - 阅读 [README.md](../README.md) 了解项目概述
   - 阅读 [DEVELOPMENT_SETUP.md](guides/DEVELOPMENT_SETUP.md) 搭建环境
   - 阅读 [ARCHITECTURE.md](architecture/ARCHITECTURE.md) 理解架构

3. **设置环境**
   - 后端：`cd backend && python -m venv venv && pip install -r requirements.txt`
   - 前端：`cd frontend && npm install`

4. **运行项目**
   - 后端：`cd backend && python src/main.py`
   - 前端：`cd frontend && npm run dev`

## 获取帮助

- 查看 [CONTRIBUTING.md](../CONTRIBUTING.md) 了解如何贡献
- 访问 [GitHub Issues](https://github.com/qq940500529/KCS/issues) 报告问题
- 阅读各子目录的 README.md 了解详细信息
