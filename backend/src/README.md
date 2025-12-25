# Backend Source Code

本目录包含 KCS 后端服务的源代码。

## 目录结构

```
src/
├── api/          # API 接口层
├── crypto/       # 加密算法模块
├── models/       # 数据模型
├── tpm/          # TPM 交互模块
├── utils/        # 工具函数
└── main.py       # 应用入口
```

## 主要模块

### API 模块 (`api/`)
- `routes.py`: API 路由定义
- `handlers.py`: 请求处理器
- `validators.py`: 输入验证
- `responses.py`: 响应格式化

### TPM 模块 (`tpm/`)
- `tpm_interface.py`: TPM 基础接口
- `core_key_manager.py`: 核心密钥管理
- `time_manager.py`: 时间读取与验证
- `tpm_operations.py`: TPM 加密操作

### 加密模块 (`crypto/`)
- `key_generator.py`: 私钥生成
- `transfer_key_generator.py`: 转换密钥生成
- `public_key_generator.py`: 公钥封装
- `key_decryptor.py`: 密钥解密/转换
- `kdf.py`: 密钥派生函数

### 数据模型 (`models/`)
- `key_models.py`: 密钥相关模型
- `config_models.py`: 配置模型
- `time_models.py`: 时间窗口模型

### 工具模块 (`utils/`)
- `logger.py`: 日志记录
- `error_handler.py`: 错误处理
- `config_loader.py`: 配置加载

## 开发指南

查看 [开发环境搭建指南](../../docs/guides/DEVELOPMENT_SETUP.md) 了解如何设置开发环境。
