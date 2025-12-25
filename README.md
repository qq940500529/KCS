# KCS - 基于 TPM 的安全密钥转换系统

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/react-18+-blue.svg)](https://reactjs.org/)
[![TPM](https://img.shields.io/badge/TPM-2.0-green.svg)](https://trustedcomputinggroup.org/)

[English](README_EN.md) | 简体中文

## 📖 项目概述

KCS (Key Conversion System) 是一个开源的、基于 Web 的安全密钥生成与转换工具。本系统利用**可信平台模块 (TPM) 2.0** 硬件特性，提供企业级的密钥管理与多重授权机制，适用于需要高安全性的文件加密、密钥分享和时间限制访问控制场景。

### 🎯 核心特性

#### 🔒 硬件级安全保障
- **TPM 硬件绑定**：核心密钥在 TPM 芯片内生成，永不导出，防止离线破解和硬件克隆
- **不可迁移密钥**：密钥与特定服务器硬件和 URL 绑定，无法在其他环境中使用
- **硬件防篡改**：即使获得服务器完全控制权，也无法提取 TPM 内的密钥材料

#### ⏰ 防篡改时间控制
- **TPM 时钟验证**：完全依赖 TPM 内部防篡改时钟，不受系统时间影响
- **数学级时间绑定**：时间作为加密算法的输入参数，而非简单的逻辑判断，无法通过修改代码绕过
- **精确时间窗口**：支持设置生效和截止时间，超出窗口自动拒绝解密

#### 👥 灵活的多重授权机制
- **多转换密钥支持**：支持生成任意数量的转换密钥（至少 1 个，建议 2-10 个）
- **全部必需验证**：解密必须提供所有转换密钥，缺一不可
- **顺序无关设计**：转换密钥可任意顺序提供，系统自动识别和验证
- **分布式授权**：每个密钥可分发给不同人员，实现多人协同授权

#### 🌐 现代化 Web 架构
- **前后端分离**：React 18+ 现代化前端 + FastAPI 高性能后端
- **RESTful API**：标准化 API 设计，自动生成交互式文档（Swagger UI）
- **响应式界面**：Material-UI 组件，支持桌面和移动端访问
- **实时验证**：前端实时参数验证，提升用户体验

## 💡 使用场景

- **企业文件加密**：为敏感文件生成加密密钥，通过多人授权机制确保安全
- **时间限制访问**：设置文档的访问时间窗口，过期自动失效
- **多方协同授权**：需要多个授权人同时提供密钥才能解密，防止单点风险
- **临时权限分享**：生成具有时间限制的访问密钥，自动过期
- **合规审计需求**：完整的操作日志和审计记录，满足合规要求

## 🏗️ 系统架构

### 技术栈

**后端**
- **Python 3.9+** - 核心语言
- **FastAPI** - 现代化异步 Web 框架，自动生成 API 文档
- **tpm2-pytss** - TPM 2.0 Python 绑定
- **cryptography** - 加密算法库
- **Uvicorn** - 高性能 ASGI 服务器

**前端**
- **React 18+** - 现代化前端框架
- **TypeScript** - 类型安全的 JavaScript
- **Vite** - 快速的构建工具
- **Material-UI / Tailwind CSS** - UI 组件库
- **Axios** - HTTP 客户端

**安全组件**
- **TPM 2.0** - 硬件安全模块
- **AES-256-GCM** - 认证加密
- **HKDF** - 密钥派生函数
- **TLS 1.2/1.3** - 传输层安全

### 密钥体系

系统涉及四种类型的密钥，每种密钥都有其特定的生成方式和用途：

| 密钥类型 | 生成方式 | 存储位置 | 用途 | 安全特性 |
|---------|---------|---------|------|---------|
| **核心密钥<br>(Core Key)** | TPM 基于硬件特征、<br>服务器 URL、随机盐生成 | TPM 芯片内部<br>(NV RAM) | 验证服务器身份，<br>参与密钥派生运算 | • 不可导出<br>• 硬件绑定<br>• URL 绑定 |
| **私钥<br>(Private Key)** | 加密级随机数生成器<br>(6-16 位字符串)<br>+ 时间窗口信息 | 用户自行保管 | 文件加密 | • 包含大小写字母、数字、符号<br>• 包含生效和截止时间<br>• 仅生成时显示一次 |
| **转换密钥<br>(Transfer Keys)** | 256 位随机数生成<br>（数量可配置，至少 1 个） | **不存储**，<br>用户分发给授权人 | 公钥→私钥转换的<br>多重授权凭证 | • 全部必需，缺一不可<br>• 顺序无关<br>• 支持任意数量 |
| **公钥<br>(Public Key)** | 系统生成<br>(Base64 编码的 JSON) | 用户分享 | 携带加密的私钥、<br>时间窗口、验证信息 | • 包含转换密钥哈希<br>• URL 绑定<br>• 时间绑定<br>• 时间窗口一致性保护 |

## 🚀 快速开始

### 环境要求

**硬件要求（生产环境）**
- 服务器必须配备 **TPM 2.0** 芯片
- CPU: 4 核以上
- 内存: 8GB 以上
- 磁盘: 50GB 以上

**软件要求**
- 操作系统: Ubuntu 20.04+ / CentOS 8+ / Windows Server 2019+
- Python: 3.8+
- Node.js: 16+ (用于前端构建)
- Docker: 20.10+ (可选，推荐)

### 开发环境快速搭建

#### 1. 克隆仓库

```bash
git clone https://github.com/qq940500529/KCS.git
cd KCS
```

#### 2. 后端设置

```bash
cd backend

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

# 安装依赖
pip install -r requirements.txt

# 启动 TPM 模拟器（开发环境）
swtpm socket --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --tpm2 --flags not-need-init &

# 设置环境变量
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

# 运行后端服务
uvicorn src.main:app --reload --host 0.0.0.0 --port 5000
```

访问 API 文档：`http://localhost:5000/docs`

#### 3. 前端设置

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

访问前端界面：`http://localhost:3000`

### Docker 快速部署

```bash
# 使用 Docker Compose 一键启动
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## 📚 核心功能说明

### 1. 密钥生成流程

```
用户配置参数 → 生成私钥 → 生成多个转换密钥 → 
TPM 派生主密钥 → 加密私钥 → 生成公钥 → 返回结果
```

**示例：生成密钥**

```bash
curl -X POST https://kcs.example.com/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{
    "private_key_config": {
      "length": 12,
      "rules": {
        "uppercase": true,
        "lowercase": true,
        "digits": true,
        "symbols": true
      }
    },
    "transfer_keys_count": 2,
    "time_window": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    }
  }'
```

**响应示例：**

```json
{
  "success": true,
  "data": {
    "private_key": "{\"key\":\"aB3$xY9#mK2p\",\"time_window\":{\"start\":\"2024-01-01T00:00:00Z\",\"end\":\"2024-12-31T23:59:59Z\"}}",
    "transfer_keys": [
      "TK-A8f9e2d1c4b5a6d7e8f9",
      "TK-B7e8d9c0b1a2f3e4d5c6"
    ],
    "public_key": "PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0=",
    "server_url": "https://kcs.example.com",
    "time_window": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    }
  }
}
```

**注意**：私钥现在是 JSON 字符串格式，包含：
- `key`: 实际的密钥字符串（6-16位随机字符）
- `time_window`: 时间窗口信息（与公钥中的时间窗口必须一致）

### 2. 密钥转换流程

```
输入公钥和所有转换密钥 → 验证密钥数量和哈希 → 
地址验证 → TPM 时间验证 → 重建主密钥 → 
解密私钥 → 验证时间窗口一致性 → 返回结果
```

**示例：转换密钥**

```bash
curl -X POST https://kcs.example.com/api/v1/keys/convert \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0=",
    "transfer_keys": [
      "TK-A8f9e2d1c4b5a6d7e8f9",
      "TK-B7e8d9c0b1a2f3e4d5c6"
    ]
  }'
```

**安全验证机制：**
✅ 必须提供所有转换密钥（数量必须匹配）
✅ 所有转换密钥必须完全正确
✅ 转换密钥可任意顺序提供（自动排序验证）
✅ 服务器 URL 必须匹配
✅ 当前时间必须在允许的时间窗口内
✅ **私钥中的时间窗口必须与公钥中的时间窗口一致**
✅ TPM 硬件必须匹配

### 3. 多转换密钥授权示例

**场景：** 企业需要 3 位管理员共同授权才能解密敏感文件

```python
# 生成密钥时设置 3 个转换密钥
result = generate_keys(
    private_key_length=12,
    transfer_keys_count=3,  # 生成 3 个转换密钥
    time_window={
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-12-31T23:59:59Z"
    }
)

# 分发转换密钥
transfer_key_1 = result["transfer_keys"][0]  # 分发给管理员 A
transfer_key_2 = result["transfer_keys"][1]  # 分发给管理员 B
transfer_key_3 = result["transfer_keys"][2]  # 分发给管理员 C

# 解密时需要所有 3 个密钥（顺序无关）
convert_key(
    public_key=result["public_key"],
    transfer_keys=[
        transfer_key_2,  # 管理员 B 提供（顺序可任意）
        transfer_key_1,  # 管理员 A 提供
        transfer_key_3   # 管理员 C 提供
    ]
)
```

## 🔐 安全特性

### 多层安全防护

| 防护层级 | 安全机制 | 防护效果 |
|---------|---------|---------|
| **硬件层** | TPM 2.0 芯片物理隔离 | 密钥永不离开硬件，防止内存读取攻击 |
| **绑定层** | 硬件特征 + URL 绑定 | 防止硬件克隆和服务器迁移攻击 |
| **时间层** | TPM 防篡改时钟 + 数学绑定 | 防止时间篡改，无法绕过时间限制 |
| **授权层** | 多转换密钥验证 | 防止单点泄露，需要多人协同授权 |
| **传输层** | TLS 1.2/1.3 强制加密 | 防止中间人攻击和数据窃听 |
| **应用层** | API 速率限制 + 审计日志 | 防止暴力破解和可疑活动追踪 |

### 威胁模型与防护

| 攻击场景 | 攻击方式 | 防护措施 | 是否成功 |
|---------|---------|---------|---------|
| **离线破解** | 获取公钥后离线暴力破解 | 转换密钥不存储，256 位强度，需全部密钥 | ❌ 失败 |
| **硬件克隆** | 克隆服务器到其他硬件 | TPM `FIXEDTPM` 属性，硬件绑定 | ❌ 失败 |
| **时间篡改** | 修改系统时间绕过限制 | 使用 TPM 时钟，时间数学绑定 | ❌ 失败 |
| **公钥时间篡改** | 修改公钥中的时间窗口延长访问期限 | 私钥中也包含时间窗口，解密后进行一致性校验 | ❌ 失败 |
| **代码修改** | 修改验证逻辑跳过检查 | 时间作为加密参数，修改代码也无法解密 | ❌ 失败 |
| **部分泄露** | 获取部分转换密钥 | 需要全部转换密钥，缺一不可 | ❌ 失败 |
| **中间人** | 拦截网络通信 | 强制 HTTPS，证书验证 | ❌ 失败 |
| **内部威胁** | 管理员滥用权限 | 审计日志，最小权限原则 | ⚠️ 受限 |

### 合规性

- ✅ **TPM 2.0**: 符合 ISO/IEC 11889 国际标准
- ✅ **加密算法**: AES-256 (FIPS 197), SHA-256 (FIPS 180-4)
- ✅ **传输安全**: TLS 1.2/1.3 (RFC 5246/8446)
- ✅ **数据保护**: 符合 GDPR 数据最小化原则
- ✅ **审计日志**: 符合 SOC 2 审计要求

## 📖 文档导航

### 📘 新手入门
- [项目结构说明](docs/PROJECT_STRUCTURE.md) - 了解项目文件组织结构
- [开发环境搭建](docs/guides/DEVELOPMENT_SETUP.md) - 快速搭建开发环境
- [贡献指南](CONTRIBUTING.md) - 如何为项目做贡献

### 🏗️ 架构与设计
- [系统架构文档](docs/architecture/ARCHITECTURE.md) - 整体架构设计和模块说明
- [安全性设计](docs/architecture/SECURITY.md) - 详细的安全机制和威胁分析
- [API 接口文档](docs/api/API.md) - 完整的 RESTful API 规范

### 🔧 开发指南
- [TPM 集成指南](docs/guides/TPM_INTEGRATION.md) - TPM 2.0 开发详解和代码示例
- [日志规范](docs/guides/LOGGING.md) - 日志记录规范和敏感信息过滤
- [测试指南](tests/README.md) - 测试策略和用例编写

### 🚀 部署运维
- [生产环境部署](docs/deployment/DEPLOYMENT.md) - 单机/Docker/高可用部署方案
- [开发就绪检查](DEVELOPMENT_READY.md) - 开发完成度和文档清单

### 📚 后端模块
- [后端代码说明](backend/src/README.md) - 后端模块结构和职责

### 🎨 前端模块
- [前端代码说明](frontend/src/README.md) - 前端组件和技术栈

## 🤝 贡献指南

我们欢迎所有形式的贡献！

### 贡献方式

- 🐛 **报告 Bug** - 发现问题请提交 [Issue](https://github.com/qq940500529/KCS/issues)
- 💡 **功能建议** - 有好的想法？我们期待听到
- 📝 **改进文档** - 文档永远可以更好
- 💻 **提交代码** - 修复 Bug 或实现新功能
- 🔍 **代码审查** - 帮助审查其他人的 PR
- ❓ **回答问题** - 在 Issues 和 Discussions 中帮助他人

### 开发流程

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

详细信息请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)

### 代码规范

- **Python**: 遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- **JavaScript/TypeScript**: 遵循 [Airbnb Style Guide](https://github.com/airbnb/javascript)
- **提交消息**: 遵循 [Conventional Commits](https://www.conventionalcommits.org/)

## 📊 项目状态

- ✅ **架构设计**: 已完成
- ✅ **文档编写**: 已完成
- ✅ **项目结构**: 已完成
- 🚧 **后端开发**: 进行中
- 🚧 **前端开发**: 进行中
- ⏳ **测试**: 待开始
- ⏳ **部署**: 待开始

## 📝 待办事项

### 第一阶段：核心功能开发
- [ ] 后端 TPM 集成
  - [ ] TPM 接口封装
  - [ ] 核心密钥管理
  - [ ] 时间管理器
- [ ] 后端加密算法
  - [ ] 私钥生成器
  - [ ] 转换密钥生成器
  - [ ] 公钥生成器
  - [ ] 密钥解密器
  - [ ] KDF 实现
- [ ] 后端 API 接口
  - [ ] API 路由定义
  - [ ] 请求处理器
  - [ ] 数据模型
  - [ ] 输入验证

### 第二阶段：前端开发
- [ ] 核心组件
  - [ ] 密钥生成表单
  - [ ] 密钥转换组件
  - [ ] 结果展示组件
- [ ] 页面开发
  - [ ] 首页
  - [ ] 密钥生成页
  - [ ] 密钥转换页
- [ ] API 集成
  - [ ] API 客户端封装
  - [ ] 错误处理
  - [ ] 状态管理

### 第三阶段：测试和优化
- [ ] 单元测试（目标 80%+ 覆盖率）
- [ ] 集成测试
- [ ] 端到端测试
- [ ] 性能优化
- [ ] 安全审计

### 第四阶段：部署和发布
- [ ] CI/CD 配置
- [ ] 部署文档
- [ ] 用户手册
- [ ] 发布 v1.0.0

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 👥 团队

- **项目维护者**: [@qq940500529](https://github.com/qq940500529)

## 🙏 致谢

感谢以下开源项目：
- [TPM2 Software Stack](https://github.com/tpm2-software) - TPM 2.0 工具和库
- [FastAPI](https://fastapi.tiangolo.com/) - 现代化的 Python Web 框架
- [React](https://reactjs.org/) - 用户界面构建库
- [cryptography](https://cryptography.io/) - Python 加密库

## 📞 联系方式

- **GitHub Issues**: [提交问题](https://github.com/qq940500529/KCS/issues)
- **GitHub Discussions**: [参与讨论](https://github.com/qq940500529/KCS/discussions)
- **Email**: qq940500529@example.com

---

<p align="center">
  如果这个项目对你有帮助，请给我们一个 ⭐️
</p>

<p align="center">
  <a href="#kcs---基于-tpm-的安全密钥转换系统">回到顶部</a>
</p>
