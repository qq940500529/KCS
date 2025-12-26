# KCS API 接口文档

## API 概述

KCS 系统基于 **FastAPI** 框架提供 RESTful API 接口，所有接口均使用 JSON 格式进行数据交互。

**技术栈**：FastAPI + Uvicorn + Pydantic

**Base URL**: `/api/v1`

**完整端点示例**:
- 生成密钥：`POST /api/v1/keys/generate`
- 转换密钥：`POST /api/v1/keys/convert`
- 健康检查：`GET /health` (不带 `/api/v1` 前缀)

**认证**: 当前版本为开源工具，暂不需要认证。生产环境建议添加 API Key 或 JWT 认证。

**交互式文档**：
- Swagger UI: `https://your-server.com/docs`
- ReDoc: `https://your-server.com/redoc`
- OpenAPI 规范: `https://your-server.com/openapi.json`

**FastAPI 特性**：
- ✅ 自动生成交互式 API 文档（Swagger UI）
- ✅ 自动数据验证（Pydantic）
- ✅ 类型提示和自动完成
- ✅ 原生异步支持，性能优异
- ✅ 简化开发，减少样板代码

## 通用响应格式

### 成功响应

```json
{
  "success": true,
  "data": {
    // 具体数据
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### 错误响应

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "错误描述",
    "details": "详细信息（可选）"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 错误码

| 错误码 | 描述 | HTTP 状态码 |
|--------|------|-------------|
| `INVALID_PARAMETER` | 参数验证失败 | 400 |
| `TPM_NOT_AVAILABLE` | TPM 不可用 | 503 |
| `CORE_KEY_NOT_FOUND` | 核心密钥未初始化 | 500 |
| `TIME_WINDOW_INVALID` | 时间窗口无效 | 400 |
| `TRANSFER_KEY_MISMATCH` | 转换密钥不匹配 | 403 |
| `SERVER_MISMATCH` | 服务器地址不匹配 | 403 |
| `TIME_OUT_OF_RANGE` | 不在允许的时间范围内（应用层检查） | 403 |
| `TIME_POLICY_DENIED` | TPM Policy 时间约束不满足（硬件层拒绝） | 403 |
| `TPM_POLICY_FAILURE` | TPM Policy 验证失败（通用） | 500 |
| `TPM_CLOCK_RESET_DETECTED` | 检测到 TPM 时钟重置，时间锚点失效 | 409 |
| `TPM_POLICY_NOT_ENABLED` | 公钥未启用 TPM Policy | 400 |
| `SEALED_OBJECT_LOAD_FAILED` | 加载 sealed object 失败 | 500 |
| `POLICY_SESSION_FAILED` | 启动或执行 policy session 失败 | 500 |
| `UNSEALED_FAILED` | Unseal 操作失败 | 500 |
| `CONVERSION_FAILED` | 密钥转换失败（通用） | 400 |
| `INTERNAL_ERROR` | 服务器内部错误 | 500 |

### 错误码说明

**时间相关错误区分**：
- `TIME_OUT_OF_RANGE`: 应用层时间检查失败（攻击者修改代码可绕过）
- `TIME_POLICY_DENIED`: TPM Policy 硬件层时间检查失败（无法绕过）

**TPM Policy 相关错误**：
- `TIME_POLICY_DENIED`: 最常见的 policy 失败，表示当前 TPM clock 不在允许的时间窗口内
- `TPM_CLOCK_RESET_DETECTED`: TPM reset_count 变化，之前的时间锚点失效，需要重新生成密钥
- `TPM_POLICY_FAILURE`: 其他 TPM Policy 相关错误

---

## 1. 系统初始化接口

### 1.1 检查 TPM 状态

**GET** `/system/tpm/status`

检查 TPM 是否可用，核心密钥是否已初始化。

**响应示例**:
```json
{
  "success": true,
  "data": {
    "tpm_available": true,
    "tpm_version": "2.0",
    "core_key_initialized": true,
    "core_key_label": "kcs-core-key-v1",
    "server_url": "https://kcs.example.com"
  }
}
```

### 1.2 初始化核心密钥

**POST** `/system/core-key/initialize`

初始化或重新生成核心密钥。**警告**：重新生成将导致所有旧公钥无法解密。

**请求体**:
```json
{
  "server_url": "https://kcs.example.com",
  "force_overwrite": false
}
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "core_key_initialized": true,
    "core_key_label": "kcs-core-key-v1",
    "server_url": "https://kcs.example.com",
    "created_at": "2024-01-01T12:00:00Z"
  }
}
```

### 1.3 获取服务器信息

**GET** `/system/info`

获取服务器基本信息。

**响应示例**:
```json
{
  "success": true,
  "data": {
    "version": "1.0.0",
    "server_url": "https://kcs.example.com",
    "tpm_available": true,
    "core_key_initialized": true
  }
}
```

---

## 2. 密钥生成接口

### 2.1 生成密钥组

**POST** `/api/v1/keys/generate`

生成私钥、转换密钥和公钥。

**请求体**:
```json
{
  "private_key_config": {
    "length": 12,
    "rules": {
      "uppercase": true,
      "lowercase": true,
      "digits": true,
      "symbols": true,
      "min_uppercase": 1,
      "min_lowercase": 1,
      "min_digits": 1,
      "min_symbols": 1
    }
  },
  "transfer_keys_count": 1,
  "time_window": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-12-31T23:59:59Z"
  },
  "tpm_policy": {
    "enabled": false
  },
  "metadata": {
    "description": "用于加密项目文件",
    "creator": "用户名（可选）"
  }
}
```

**参数说明**:
- `private_key_config.length`: 私钥长度，范围 6-16
- `private_key_config.rules`: 字符集规则
- `transfer_keys_count`: **转换密钥数量，至少 1 个，无上限**（建议 2-10 个）
- `time_window`: 允许解密的时间窗口
- `tpm_policy.enabled`: **是否启用 TPM Policy 强制时间窗口**（可选，默认 false）
- `metadata`: 可选的元数据信息

**TPM Policy 配置说明**：
- `enabled: false` (默认): 应用层时间验证（时间参与密钥派生）
- `enabled: true`: TPM Policy 硬件层强制时间窗口（PolicyCounterTimer）

**安全级别对比**：
| 配置 | 防护能力 | 适用场景 |
|------|---------|---------|
| `enabled: false` | 应用层防护 | 常规场景，信任服务器管理员 |
| `enabled: true` | 硬件层不可绕过 | 高安全场景，防止代码修改攻击 |

**重要说明**：
- 生成的所有转换密钥在解密时**必须全部提供且正确**
- **输入顺序无关**：转换密钥可以任意顺序提供
- 建议根据安全需求和使用场景配置合适的数量：
  - **2-3 个**：小团队或简单授权场景
  - **5-10 个**：中型组织或多部门授权
  - **10+ 个**：大型组织或高安全性要求场景
- 每个转换密钥应分发给不同的授权人员，确保多人授权机制
- **TPM Policy** 需要真实 TPM 2.0 硬件，swtpm 仅用于开发测试

**响应示例**:
```json
{
  "success": true,
  "data": {
    "private_key": "aB3$xY9#mK2p",
    "transfer_keys": [
      "TK-A8f9e2d1c4b5a6d7e8f9",
      "TK-B7e8d9c0b1a2f3e4d5c6"
    ],
    "public_key": "PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0=",
    "server_url": "https://kcs.example.com",
    "time_window": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    },
    "created_at": "2024-01-01T12:00:00Z"
  }
}
```

**前端功能**：

生成密钥后提供便捷的导出和分发功能：

1. 公钥：支持直接复制或导出为 `.pub` 文件
2. 转换密钥：支持单独复制或导出为 `.tkn` 文件，可批量打包为 ZIP
3. 私钥：仅在生成时显示一次，支持复制

### 2.2 验证私钥格式

**POST** `/api/v1/keys/validate-format`

验证私钥是否符合指定规则（用于前端实时验证）。

**请求体**:
```json
{
  "private_key": "aB3$xY9#mK2p",
  "rules": {
    "length": 12,
    "uppercase": true,
    "lowercase": true,
    "digits": true,
    "symbols": true
  }
}
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "valid": true,
    "details": {
      "length_valid": true,
      "has_uppercase": true,
      "has_lowercase": true,
      "has_digits": true,
      "has_symbols": true
    }
  }
}
```

---

## 3. 密钥转换接口

### 3.1 转换公钥为私钥

**POST** `/api/v1/keys/convert`

使用公钥和所有转换密钥还原私钥。

**前端输入方式**：

1. 公钥：支持手动粘贴或上传 `.pub` 文件
2. 转换密钥：支持逐个输入、批量粘贴或上传 `.tkn` 文件（含 ZIP 包）

**请求体**:
```json
{
  "public_key": "PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0=",
  "transfer_keys": [
    "TK-A8f9e2d1c4b5a6d7e8f9",
    "TK-B7e8d9c0b1a2f3e4d5c6"
  ]
}
```

**验证要求**：
- ✅ 必须提供生成时创建的所有转换密钥
- ✅ 所有转换密钥必须完全正确
- ✅ 输入顺序无关：密钥可任意顺序提供，系统自动排序验证
- ❌ 缺少任何一个转换密钥将导致解密失败
- ❌ 任何一个转换密钥错误将导致解密失败

**响应示例**（成功）:
```json
{
  "success": true,
  "data": {
    "private_key": "aB3$xY9#mK2p",
    "time_window": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z",
      "current_time": "2024-06-15T10:30:00Z"
    },
    "server_url": "https://kcs.example.com",
    "metadata": {
      "description": "用于加密项目文件"
    }
  }
}
```

**响应示例**（时间超出范围）:
```json
{
  "success": false,
  "error": {
    "code": "TIME_OUT_OF_RANGE",
    "message": "当前时间不在允许的解密时间范围内",
    "details": {
      "current_time": "2025-01-15T10:30:00Z",
      "allowed_window": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-12-31T23:59:59Z"
      }
    }
  }
}
```

**响应示例**（服务器地址不匹配）:
```json
{
  "success": false,
  "error": {
    "code": "SERVER_MISMATCH",
    "message": "当前服务器地址不匹配",
    "details": {
      "correct_url": "https://kcs.example.com"
    }
  }
}
```

**响应示例**（转换密钥不匹配）:
```json
{
  "success": false,
  "error": {
    "code": "TRANSFER_KEY_MISMATCH",
    "message": "转换密钥不匹配"
  }
}
```

**响应示例**（TPM Policy 时间约束不满足）:
```json
{
  "success": false,
  "error": {
    "code": "TIME_POLICY_DENIED",
    "message": "TPM Policy 时间约束不满足，硬件层拒绝 unseal",
    "details": {
      "current_tick": 1500000000,
      "allowed_window": {
        "start_tick": 1000000,
        "end_tick": 1200000
      }
    }
  }
}
```

**响应示例**（TPM 时钟重置检测）:
```json
{
  "success": false,
  "error": {
    "code": "TPM_CLOCK_RESET_DETECTED",
    "message": "检测到 TPM 时钟已重置，时间锚点失效，请重新生成密钥"
  }
}
```

### 3.2 解析公钥信息

**POST** `/api/v1/keys/parse-public-key`

解析公钥中的非敏感信息（不需要转换密钥）。

**请求体**:
```json
{
  "public_key": "PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0="
}
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "version": 1,
    "server_url": "https://kcs.example.com",
    "time_window": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    },
    "created_at": "2024-01-01T12:00:00Z",
    "transfer_keys_count": 2,
    "tpm_policy": {
      "enabled": true,
      "type": "PolicyCounterTimer",
      "time_window_ticks": {
        "start_tick": 1000000,
        "end_tick": 2000000
      }
    },
    "metadata": {
      "description": "用于加密项目文件"
    }
  }
}
```

**重要信息**：
- `transfer_keys_count`: 显示生成时创建的转换密钥数量
- `tpm_policy.enabled`: 是否启用了 TPM Policy 强制时间窗口
- `tpm_policy.type`: Policy 类型（如 PolicyCounterTimer）
- 解密时必须提供对应数量的所有转换密钥

---

## 4. 时间验证接口

### 4.1 获取 TPM 时间

**GET** `/time/tpm-time`

获取 TPM 的当前时间（不依赖系统时间）。

**响应示例**:
```json
{
  "success": true,
  "data": {
    "tpm_time": "2024-06-15T10:30:00Z",
    "tpm_clock_info": {
      "clock": 1234567890,
      "reset_count": 0,
      "restart_count": 0
    }
  }
}
```

### 4.2 验证时间窗口

**POST** `/time/validate-window`

验证指定时间窗口是否有效。

**请求体**:
```json
{
  "time_window": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-12-31T23:59:59Z"
  }
}
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "valid": true,
    "current_time": "2024-06-15T10:30:00Z",
    "in_range": true,
    "time_until_start": 0,
    "time_until_end": 15638400
  }
}
```

---

## 5. 健康检查接口

### 5.1 健康检查

**GET** `/health`

检查服务是否正常运行。

**响应示例**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "tpm_available": true,
    "core_key_status": "initialized",
    "uptime": 86400
  }
}
```

### 5.2 就绪检查

**GET** `/ready`

检查服务是否准备好接受请求。

**响应示例**:
```json
{
  "success": true,
  "data": {
    "ready": true
  }
}
```

---

## 接口调用示例

### Python 示例

```python
import requests
import json

# 生成密钥
def generate_keys():
    url = "https://kcs.example.com/api/v1/keys/generate"
    payload = {
        "private_key_config": {
            "length": 12,
            "rules": {
                "uppercase": True,
                "lowercase": True,
                "digits": True,
                "symbols": True
            }
        },
        "transfer_keys_count": 1,
        "time_window": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-12-31T23:59:59Z"
        }
    }
    
    response = requests.post(url, json=payload)
    return response.json()

# 转换密钥
def convert_key(public_key, transfer_keys):
    url = "https://kcs.example.com/api/v1/keys/convert"
    payload = {
        "public_key": public_key,
        "transfer_keys": transfer_keys
    }
    
    response = requests.post(url, json=payload)
    return response.json()

# 使用示例
result = generate_keys()
if result["success"]:
    print("Private Key:", result["data"]["private_key"])
    print("Transfer Keys:", result["data"]["transfer_keys"])
    print("Public Key:", result["data"]["public_key"])
```

### JavaScript 示例

```javascript
// 生成密钥
async function generateKeys() {
  const url = "https://kcs.example.com/api/v1/keys/generate";
  const payload = {
    private_key_config: {
      length: 12,
      rules: {
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true
      }
    },
    transfer_keys_count: 1,
    time_window: {
      start: "2024-01-01T00:00:00Z",
      end: "2024-12-31T23:59:59Z"
    }
  };
  
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  
  return await response.json();
}

// 转换密钥
async function convertKey(publicKey, transferKeys) {
  const url = "https://kcs.example.com/api/v1/keys/convert";
  const payload = {
    public_key: publicKey,
    transfer_keys: transferKeys
  };
  
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  
  return await response.json();
}

// 使用示例
generateKeys().then(result => {
  if (result.success) {
    console.log("Private Key:", result.data.private_key);
    console.log("Transfer Keys:", result.data.transfer_keys);
    console.log("Public Key:", result.data.public_key);
  }
});
```

---

## 文件格式规范

### 公钥文件格式 (`.pub`)

公钥文件为纯文本格式，包含完整的公钥字符串：

```
PUB_eyJ2ZXJzaW9uIjoxLCJkYXRhIjoiLi4uIn0=
```

文件命名建议：`key_YYYYMMDD_HHMMSS.pub`

### 转换密钥文件格式 (`.tkn`)

转换密钥文件为纯文本格式，包含单个转换密钥：

```
TK-A8f9e2d1c4b5a6d7e8f9
```

文件命名建议：`transfer_key_1.tkn`、`transfer_key_2.tkn` 等

文件名中的序号仅用于用户识别和管理，系统使用时支持任意顺序输入，无需按序号排列。

### 批量转换密钥包 (`.zip`)

包含多个 `.tkn` 文件的 ZIP 压缩包，用于批量分发转换密钥。

---

## 注意事项

1. HTTPS 必需：生产环境必须使用 HTTPS 协议
2. 速率限制：建议实施 API 速率限制防止滥用
3. 日志记录：所有敏感操作应记录审计日志
4. 错误处理：客户端应妥善处理各种错误情况
5. 私钥安全：私钥应仅在需要时显示，不应长期存储在客户端
6. 文件安全：导出的公钥和转换密钥文件应妥善保管，避免泄露
