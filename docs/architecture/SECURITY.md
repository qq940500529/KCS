# KCS 安全性设计文档

## 1. 安全设计原则

KCS 系统基于以下安全设计原则：

### 1.1 纵深防御 (Defense in Depth)

系统采用多层安全机制，即使某一层被突破，其他层仍能提供保护：

1. **硬件层**：TPM 芯片提供硬件级别的安全保障
2. **加密层**：使用强加密算法保护密钥
3. **验证层**：多重授权验证机制
4. **传输层**：HTTPS 加密通信
5. **应用层**：输入验证、速率限制、日志审计

### 1.2 最小权限原则 (Principle of Least Privilege)

- 每个组件仅拥有完成其功能所需的最小权限
- TPM 核心密钥仅用于必要的加密操作
- 服务进程以非特权用户运行

### 1.3 零信任架构 (Zero Trust)

- 不信任任何输入，所有数据都需要验证
- 每次操作都需要重新验证授权
- 不依赖网络边界防护

## 2. 威胁模型

### 2.1 识别的威胁

| 威胁类型 | 描述 | 风险等级 | 缓解措施 |
|---------|------|----------|----------|
| 暴力破解 | 攻击者尝试枚举转换密钥 | 高 | 速率限制、复杂密钥、审计日志 |
| 中间人攻击 | 拦截客户端与服务器通信 | 高 | 强制 HTTPS、证书验证 |
| 离线攻击 | 获取公钥后离线破解 | 高 | 转换密钥不存储、TPM 绑定 |
| 硬件克隆 | 克隆服务器硬件 | 高 | TPM 硬件绑定、不可导出密钥 |
| 时间篡改 | 修改系统时间绕过限制 | 中 | 使用 TPM 时钟、数学绑定 |
| 内部威胁 | 服务器管理员滥用权限 | 中 | 审计日志、最小权限 |
| DDoS 攻击 | 大量请求导致服务不可用 | 中 | 速率限制、负载均衡 |
| SQL 注入 | 恶意 SQL 代码注入 | 低 | 参数化查询（如使用数据库） |
| XSS 攻击 | 跨站脚本攻击 | 低 | 输入验证、CSP 头 |

### 2.2 信任边界

```
┌─────────────────────────────────────────────────────────┐
│               不信任区域 (Internet)                       │
│                    ▲                                     │
│                    │ HTTPS                               │
└────────────────────┼─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│              信任边界 (Server)                            │
│  ┌────────────────┐         ┌────────────────┐          │
│  │  Web 应用层    │◄───────►│  业务逻辑层    │          │
│  └────────────────┘         └────────────────┘          │
│                                    ▲                      │
│                                    │                      │
│  ┌─────────────────────────────────▼──────────────────┐  │
│  │            可信硬件边界 (TPM)                       │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │  │
│  │  │ 核心密钥 │  │ TPM 时钟 │  │ 加密引擎 │         │  │
│  │  └──────────┘  └──────────┘  └──────────┘         │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 3. 密钥安全

### 3.1 核心密钥保护

**生成机制**：
```python
def generate_core_key(tpm, server_url, salt):
    """
    核心密钥生成算法
    
    输入：
    - TPM Endorsement Key (硬件特征)
    - 服务器 URL
    - 随机盐值
    
    输出：
    - 存储在 TPM 中的不可导出密钥句柄
    """
    # 读取 EK 公钥（硬件指纹）
    ek_pub = tpm.get_endorsement_key_public()
    
    # 组合输入
    input_data = hash(ek_pub + server_url + salt)
    
    # 在 TPM 内部生成密钥
    core_key_handle = tpm.create_primary(
        hierarchy=TPM_RH_OWNER,
        template={
            "type": TPM_ALG_SYMCIPHER,
            "algorithm": TPM_ALG_AES,
            "keyBits": 256,
            "mode": TPM_ALG_CFB,
            "objectAttributes": 
                FIXEDTPM |        # 不可迁移
                FIXEDPARENT |     # 不可重新包装
                SENSITIVEDATAORIGIN |  # TPM 生成
                USERWITHAUTH,     # 需要授权
        },
        sensitive_data=input_data
    )
    
    # 持久化
    tpm.evict_control(core_key_handle, 0x81010001)
    
    return 0x81010001
```

**安全特性**：
- ✅ 绑定到特定硬件（EK）
- ✅ 绑定到特定 URL
- ✅ 设置 `FIXEDTPM` 属性，不可导出
- ✅ 设置 `FIXEDPARENT` 属性，不可重新包装
- ✅ 使用 TPM 内部随机数生成器
- ✅ 持久化到 NV 存储

### 3.2 私钥安全

**生成要求**：
- 长度：6-16 位（可配置）
- 必须包含：大写字母、小写字母、数字、特殊符号
- 使用加密级随机数生成器（`secrets` 模块）

```python
import secrets
import string

def generate_private_key(length=12):
    """
    生成符合安全要求的私钥
    """
    if length < 6 or length > 16:
        raise ValueError("Length must be between 6 and 16")
    
    # 字符集
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # 确保至少包含每种字符各一个
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    
    # 填充剩余长度
    all_chars = uppercase + lowercase + digits + symbols
    password += [secrets.choice(all_chars) for _ in range(length - 4)]
    
    # 随机打乱
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)
```

**时间窗口嵌入机制**：

时间窗口信息通过核心密钥参与的加密转换嵌入到密钥派生过程中：

```python
def derive_encryption_key_with_time(core_key, transfer_keys, time_window, tpm_time_seed):
    """
    派生加密密钥时将时间窗口信息嵌入
    
    核心密钥参与时间窗口的加密转换，使得加密密钥依赖于时间窗口。
    修改公钥中的时间窗口会导致派生出错误的加密密钥，无法正确解密私钥。
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    # 将时间窗口序列化
    time_data = f"{time_window['start']}|{time_window['end']}".encode()
    
    # 使用核心密钥对时间窗口进行加密转换
    time_hash = hashlib.sha256(core_key + time_data).digest()
    
    # 组合所有转换密钥
    sorted_keys = sorted(transfer_keys)
    combined_keys = '|'.join(sorted_keys).encode()
    
    # 派生加密密钥
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=time_hash,
        info=b'kcs-private-key-encryption'
    )
    
    input_material = core_key + combined_keys + time_data + tpm_time_seed.to_bytes(8, 'big')
    encryption_key = kdf.derive(input_material)
    
    return encryption_key
```

**存储安全**：
- ❌ 服务器不存储私钥
- ✅ 私钥仅在生成时显示一次
- ✅ 加密后包含在公钥中
- ✅ 时间窗口通过核心密钥嵌入到派生过程
- ⚠️ 用户需自行安全保管私钥

### 3.3 转换密钥安全

**生成机制**：
```python
def generate_transfer_keys(count=1):
    """
    生成多个转换密钥
    
    Args:
        count: 转换密钥数量（至少 1 个，无上限）
    
    Returns:
        转换密钥列表
    """
    if count < 1:
        raise ValueError("Transfer key count must be at least 1")
    
    transfer_keys = []
    for i in range(count):
        # 每个密钥使用 256 位随机数据
        random_bytes = secrets.token_bytes(32)
        hex_string = random_bytes.hex()
        transfer_keys.append(f"TK-{hex_string}")
    
    return transfer_keys
```

**安全特性**：
- ✅ 每个转换密钥 256 位随机数据
- ✅ 使用加密级随机数生成器
- ❌ 不在服务器存储
- ❌ 不在公钥中明文存储（仅存所有密钥的哈希）
- ⚠️ 用户需安全传输给接收者

**多密钥验证机制**：
```python
def verify_transfer_keys(provided_keys, stored_hashes):
    """
    验证所有转换密钥
    
    Args:
        provided_keys: 用户提供的转换密钥列表（顺序可任意）
        stored_hashes: 公钥中存储的密钥哈希列表
    
    Returns:
        bool: 所有密钥都正确返回 True，否则返回 False
    """
    import hashlib
    
    # 1. 验证数量
    if len(provided_keys) != len(stored_hashes):
        return False
    
    # 2. 计算每个密钥的哈希（顺序无关，使用集合）
    provided_hashes = set()
    for key in provided_keys:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        provided_hashes.add(key_hash)
    
    # 3. 验证所有哈希都匹配（集合比较，自动处理顺序）
    stored_hashes_set = set(stored_hashes)
    
    # 所有密钥的哈希必须完全匹配
    return provided_hashes == stored_hashes_set
```

**安全要求**：
- ✅ 解密时必须提供所有转换密钥
- ✅ 所有转换密钥必须完全正确
- ✅ **输入顺序无关**：转换密钥可任意顺序提供（使用集合比较）
- ✅ 支持任意数量的转换密钥（至少 1 个）
- ❌ 缺少任何一个密钥都无法解密
- ❌ 任何一个密钥错误都无法解密

### 3.4 公钥结构

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "encrypted_data": {
    "ciphertext": "base64_encoded",
    "nonce": "base64_encoded",
    "tag": "base64_encoded"
  },
  "metadata": {
    "server_url_hash": "sha256_hash",
    "time_window": {
      "start": "timestamp",
      "end": "timestamp"
    },
    "tpm_time_seed": "integer",
    "transfer_keys_count": 2,
    "transfer_keys_hashes": [
      "sha256_hash_1",
      "sha256_hash_2"
    ],
    "created_at": "timestamp"
  }
}
```

**安全特性**：
- ✅ 使用 AES-256-GCM 认证加密
- ✅ URL 仅存哈希，防止信息泄露
- ✅ 存储转换密钥数量（`transfer_keys_count`）
- ✅ 存储所有转换密钥的哈希（`transfer_keys_hashes`）
- ✅ 转换密钥仅存哈希，不存明文
- ✅ 包含时间绑定信息
- ✅ 时间窗口通过核心密钥嵌入派生过程
- ✅ Base64 编码便于传输

**时间窗口嵌入验证**：

```python
def validate_time_embedded_key(public_key, transfer_keys, core_key, tpm):
    """
    验证时间窗口嵌入的密钥
    
    时间窗口通过核心密钥参与加密密钥派生。
    修改时间窗口导致派生出错误的加密密钥，无法正确解密私钥。
    """
    import json
    import base64
    
    # 解析公钥
    public_key_data = json.loads(base64.b64decode(public_key[4:]))
    time_window = public_key_data['metadata']['time_window']
    
    # 使用公钥中的时间窗口派生加密密钥
    encryption_key = derive_encryption_key_with_time(
        core_key,
        transfer_keys,
        time_window,
        public_key_data['metadata']['tpm_time_seed']
    )
    
    # 尝试解密私钥
    try:
        decrypted = decrypt_with_key(
            encryption_key,
            public_key_data['encrypted_data']
        )
        return validate_private_key_format(decrypted)
    except Exception:
        raise SecurityError("解密失败")
```

## 4. 时间验证安全

### 4.1 TPM 时钟机制

**为什么不使用系统时间？**

| 系统时间 | TPM 时钟 |
|---------|---------|
| ❌ 可被管理员修改 | ✅ 硬件维护，防篡改 |
| ❌ 可被恶意软件修改 | ✅ 独立于操作系统 |
| ❌ 依赖 NTP 同步 | ✅ 单调递增计数器 |
| ❌ 可回滚 | ✅ Reset 计数器可检测 |

**TPM 时间读取**：

```python
def get_tpm_time_secure(tpm):
    """
    安全地读取 TPM 时间
    """
    time_info = tpm.read_clock()
    
    # 返回多个参数用于验证
    return {
        "clock": time_info.clock,           # 当前时钟值（毫秒）
        "reset_count": time_info.resetCount,    # TPM 重置次数
        "restart_count": time_info.restartCount, # 系统重启次数
        "safe": time_info.safe              # 时钟是否可信
    }
```

### 4.2 时间数学绑定

时间不仅是验证条件，还是加密参数。时间窗口通过核心密钥的加密转换嵌入到密钥派生过程中。

```python
def derive_encryption_key_with_time_binding(core_key, transfer_keys, time_window, tpm_time_seed):
    """
    派生加密密钥，时间窗口通过核心密钥嵌入
    
    如果时间窗口被篡改，派生出的密钥错误，解密失败
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    # 将时间窗口序列化
    time_data = f"{time_window['start']}|{time_window['end']}".encode()
    
    # 使用核心密钥对时间窗口进行加密转换
    time_hash = hashlib.sha256(core_key + time_data).digest()
    
    # 组合所有转换密钥
    sorted_keys = sorted(transfer_keys)
    combined_keys = '|'.join(sorted_keys).encode()
    
    # 派生加密密钥
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=time_hash,  # 时间窗口通过核心密钥转换后作为盐值
        info=b'kcs-private-key-encryption'
    )
    
    input_material = core_key + combined_keys + time_data + tpm_time_seed.to_bytes(8, 'big')
    encryption_key = kdf.derive(input_material)
    
    return encryption_key

def verify_time_window(tpm, time_window):
    """
    验证当前时间是否在允许窗口内
    """
    current_time = get_tpm_time_secure(tpm)
    
    # 检查 TPM 是否被重置过
    if current_time['reset_count'] != stored_reset_count:
        raise SecurityError("TPM has been reset")
    
    # 检查时间范围
    current_clock = current_time['clock']
    if not (time_window['start'] <= current_clock <= time_window['end']):
        raise TimeWindowError(
            f"Current time {current_clock} not in window "
            f"[{time_window['start']}, {time_window['end']}]"
        )
    
    return True
```

**攻击场景分析**：

| 攻击方法 | 是否成功 | 原因 |
|---------|---------|------|
| 修改系统时间 | ❌ 失败 | 使用 TPM 时钟，不受影响 |
| 修改代码跳过时间检查 | ❌ 失败 | 时间是加密参数，修改代码也解不出 |
| 修改公钥中的时间窗口 | ❌ 失败 | 时间窗口通过核心密钥嵌入派生过程，篡改导致解密失败 |
| 克隆 TPM 状态 | ❌ 失败 | TPM 状态不可导出 |
| 回滚 TPM 时钟 | ❌ 失败 | Reset 计数器会改变 |

## 5. 网络通信安全

### 5.1 HTTPS 强制

**Nginx 配置**：

```nginx
# 强制重定向 HTTP 到 HTTPS
server {
    listen 80;
    server_name kcs.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name kcs.example.com;
    
    # 现代 SSL 配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256...';
    ssl_prefer_server_ciphers off;
    
    # HSTS（强制 HTTPS）
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # 其他安全头
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
}
```

### 5.2 证书管理

- 使用 Let's Encrypt 或商业证书
- 定期自动续期
- 监控证书过期时间
- 使用证书透明度日志

### 5.3 API 安全

**速率限制（FastAPI + SlowAPI）**：

```python
from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

app = FastAPI()

# 配置速率限制器
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/v1/keys/generate")
@limiter.limit("10/hour")  # 密钥生成限制更严格
async def generate_keys(request: Request):
    pass

@app.post("/api/v1/keys/convert")
@limiter.limit("100/hour")  # 转换稍宽松
async def convert_keys(request: Request):
    pass
```

**输入验证（Pydantic 自动验证）**：

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator
from datetime import datetime

app = FastAPI()

class TimeWindow(BaseModel):
    start: datetime
    end: datetime

class KeyGenerationRequest(BaseModel):
    private_key_length: int = Field(..., ge=6, le=16, description="私钥长度，6-16位")
    transfer_keys_count: int = Field(..., ge=1, description="转换密钥数量，至少 1 个")
    time_window: TimeWindow
    
    @field_validator('time_window')
    @classmethod
    def validate_time_window(cls, v: TimeWindow) -> TimeWindow:
        if v.start >= v.end:
            raise ValueError("Start time must be before end time")
        
        duration = (v.end - v.start).total_seconds()
        if duration > 365 * 24 * 3600:  # 最长1年
            raise ValueError("Time window too large (max 1 year)")
        
        return v

# FastAPI 会自动验证并返回清晰的错误消息
@app.post("/api/v1/keys/generate")
async def generate_keys(request: KeyGenerationRequest):
    # 数据已自动验证，类型安全
    return {"status": "success"}
```

**FastAPI 验证优势**：
- ✅ 自动类型检查和转换
- ✅ 清晰的错误消息（422 Unprocessable Entity）
- ✅ 自动生成文档中的参数说明
- ✅ IDE 支持自动完成和类型提示
```

## 6. 审计与日志

### 6.1 日志记录规范

**日志框架**：Python `logging` + `python-json-logger`（结构化日志）

**日志分类**：

1. **应用日志** (`/var/log/kcs/app.log`)
   - 记录内容：系统启动/停止、配置加载、健康检查
   - 级别：INFO, WARNING, ERROR
   - 不含敏感信息

2. **审计日志** (`/var/log/kcs/audit.log`)
   - 记录内容：所有密钥操作（生成、转换）
   - 级别：INFO（成功操作）、WARNING（失败尝试）
   - **严禁记录私钥、转换密钥**

3. **安全日志** (`/var/log/kcs/security.log`)
   - 记录内容：可疑活动、暴力破解尝试、异常访问
   - 级别：WARNING, ERROR, CRITICAL
   - 用于安全监控和告警

### 6.2 审计日志详细说明

**允许记录的信息**：

```python
import logging
import json
from datetime import datetime

audit_logger = logging.getLogger('audit')

def log_key_generation(user_ip, request_data, result):
    """
    记录密钥生成操作
    
    记录内容：
    - 时间戳、操作类型、客户端 IP
    - 请求参数（密钥长度、转换密钥数量、时间窗口）
    - 操作结果（成功/失败）
    - 公钥哈希值（SHA256，不是公钥本身）
    
    不记录：
    - ❌ 私钥（Private Key）
    - ❌ 转换密钥（Transfer Key）
    - ❌ 公钥完整内容
    """
    audit_logger.info(json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "KEY_GENERATION",
        "client_ip": user_ip,
        "request_params": {
            "key_length": request_data['private_key_length'],
            "transfer_keys_count": request_data['transfer_keys_count'],
            "time_window_start": request_data['time_window']['start'],
            "time_window_end": request_data['time_window']['end']
        },
        "success": result['success'],
        "public_key_hash": hashlib.sha256(result.get('public_key', '').encode()).hexdigest(),
        "duration_ms": result.get('duration_ms', 0)
    }))

def log_key_conversion(user_ip, public_key_hash, success, reason=None):
    """
    记录密钥转换操作
    
    记录内容：
    - 时间戳、操作类型、客户端 IP
    - 公钥哈希值（用于关联操作，不是公钥本身）
    - 操作结果和失败原因
    
    不记录：
    - ❌ 转换密钥（Transfer Key）
    - ❌ 还原出的私钥（Private Key）
    - ❌ 公钥完整内容
    """
    log_level = logging.WARNING if not success else logging.INFO
    audit_logger.log(log_level, json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "KEY_CONVERSION",
        "client_ip": user_ip,
        "public_key_hash": public_key_hash,
        "success": success,
        "failure_reason": reason if not success else None,
    }))
```

**敏感信息过滤**：

```python
import hashlib

def sanitize_log_data(data):
    """
    清理日志数据，移除所有敏感信息
    
    此函数确保以下信息永远不会被记录：
    - 私钥（private_key）
    - 转换密钥（transfer_key, transfer_keys）
    - 公钥完整内容（public_key，仅记录哈希）
    - TPM 内部密钥材料
    """
    # 定义所有敏感字段
    sensitive_keys = [
        'private_key', 
        'transfer_key', 
        'transfer_keys',
        'public_key',  # 仅记录哈希，不记录完整内容
        'core_key_material',
        'tpm_key_handle',
        'encryption_key',
        'master_key'
    ]
    
    sanitized = data.copy()
    
    # 移除敏感字段
    for key in sensitive_keys:
        if key in sanitized:
            sanitized[key] = '***REDACTED***'
    
    # 如果有公钥，替换为哈希值
    if 'public_key' in data:
        sanitized['public_key_hash'] = hashlib.sha256(
            data['public_key'].encode()
        ).hexdigest()
    
    return sanitized

# 使用示例
def api_handler(request_data):
    # 业务逻辑
    result = process_request(request_data)
    
    # 记录日志前先清理
    safe_data = sanitize_log_data(request_data)
    safe_result = sanitize_log_data(result)
    
    logger.info(f"Request: {safe_data}, Result: {safe_result}")
```

### 6.3 日志分析和监控

**监控指标**：

- 监控失败的转换尝试（可能的暴力破解）
- 识别异常的生成模式
- 追踪密钥使用统计
- 检测可疑的 IP 地址

### 6.4 安全事件响应

```python
def detect_brute_force(ip_address, time_window=3600):
    """
    检测暴力破解攻击
    """
    recent_failures = get_failed_attempts(ip_address, time_window)
    
    if recent_failures > 10:
        # 触发告警
        alert_security_team(
            f"Possible brute force from {ip_address}: "
            f"{recent_failures} failures in {time_window}s"
        )
        
        # 临时封禁 IP
        block_ip(ip_address, duration=3600)
        
        return True
    
    return False
```

## 7. 数据保护

### 7.1 敏感数据处理

**原则**：
- 🔴 **私钥**：仅在生成时显示，不记录日志
- 🟠 **转换密钥**：不存储，不记录日志
- 🟡 **公钥**：可以记录哈希值
- 🟢 **服务器 URL**：可以记录

```python
def sanitize_log_data(data):
    """
    清理日志数据，移除敏感信息
    """
    sensitive_keys = ['private_key', 'transfer_key', 'transfer_keys']
    
    sanitized = data.copy()
    for key in sensitive_keys:
        if key in sanitized:
            sanitized[key] = '***REDACTED***'
    
    return sanitized
```

### 7.2 内存安全

```python
import ctypes

def secure_delete(data):
    """
    安全删除内存中的敏感数据
    """
    if isinstance(data, str):
        data = data.encode()
    
    # 覆盖内存
    location = id(data)
    size = len(data)
    ctypes.memset(location, 0, size)
    
    # 删除引用
    del data

# 使用示例
private_key = generate_private_key()
# ... 使用私钥 ...
secure_delete(private_key)
```

## 8. 安全测试

### 8.1 渗透测试检查清单

- [ ] 尝试暴力破解转换密钥
- [ ] 尝试修改系统时间绕过限制
- [ ] 尝试 SQL 注入（如使用数据库）
- [ ] 尝试 XSS 攻击
- [ ] 尝试 CSRF 攻击
- [ ] 尝试中间人攻击
- [ ] 测试速率限制是否生效
- [ ] 测试证书验证
- [ ] 测试错误信息是否泄露敏感信息

### 8.2 安全审计

定期进行：
- 代码审计
- 依赖库漏洞扫描
- 配置审查
- 日志审查
- 渗透测试

## 9. 合规性

### 9.1 数据保护法规

根据使用场景，可能需要遵守：
- GDPR（欧盟）
- CCPA（加利福尼亚）
- 中国《数据安全法》
- 中国《个人信息保护法》

### 9.2 加密标准

- ✅ TPM 2.0：ISO/IEC 11889
- ✅ AES-256：FIPS 197
- ✅ SHA-256：FIPS 180-4
- ✅ TLS 1.2/1.3：RFC 5246/8446

## 10. 安全最佳实践

### 开发阶段
1. ✅ 遵循安全编码规范
2. ✅ 代码审查关注安全问题
3. ✅ 使用静态代码分析工具
4. ✅ 定期更新依赖库

### 部署阶段
1. ✅ 使用最小权限原则
2. ✅ 启用所有安全功能
3. ✅ 配置防火墙和 IDS
4. ✅ 定期备份（不包括 TPM 密钥）

### 运维阶段
1. ✅ 监控安全事件
2. ✅ 定期安全审计
3. ✅ 及时应用安全补丁
4. ✅ 制定安全事件响应计划

---

**安全是一个持续的过程，而非一次性任务。**
