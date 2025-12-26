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
| 时间篡改 | 修改系统时间绕过限制 | 中 | 使用 TPM 时钟、应用层绑定 |
| 代码修改攻击 | 攻击者获得 root 权限并修改应用代码绕过时间检查 | 高 | 应用层防护受限，TPM Policy 强制（需配置） |
| 内部威胁 | 服务器管理员滥用权限 | 中 | 审计日志、最小权限、TPM Policy |
| DDoS 攻击 | 大量请求导致服务不可用 | 中 | 速率限制、负载均衡 |
| SQL 注入 | 恶意 SQL 代码注入 | 低 | 参数化查询（如使用数据库） |
| XSS 攻击 | 跨站脚本攻击 | 低 | 输入验证、CSP 头 |

### 2.2 威胁分析：代码修改攻击

**攻击场景**：攻击者获得服务器完全控制权限（root 或管理员权限），可以修改应用代码。

**攻击目标**：绕过时间窗口检查，在窗口外仍能解密并返回私钥。

**防护层级对比**：

| 防护方案 | 防护能力 | 攻击者是否成功 | 说明 |
|---------|---------|--------------|------|
| 应用层时间检查 | 可被绕过 | ✅ 成功 | 攻击者修改代码跳过时间验证逻辑 |
| 应用层密钥派生绑定 | 可被绕过 | ✅ 成功 | 攻击者修改代码直接返回解密后的私钥 |
| TPM Policy（PolicyCounterTimer） | 不可绕过 | ❌ 失败 | TPM 硬件拒绝 unseal/decrypt，应用层无法获取密钥材料 |
| 客户端持密 + 服务器 blind signing | 不可绕过 | ❌ 失败 | 私钥不在服务器，服务器仅执行盲签名 |

**结论**：当威胁模型包含"攻击者获得服务器完全控制权限"时，应用层防护不足，需要 TPM Policy 或客户端持密方案。

### 2.3 信任边界

```
┌─────────────────────────────────────────────────────────┐
│               不信任区域 (Internet)                       │
│                    ▲                                     │
│                    │ HTTPS                               │
└────────────────────┼─────────────────────────────────────┘
                     │
┌────────────────────▼─────────────────────────────────────┐
│           应用信任边界 (Server Application)               │
│  ┌────────────────┐         ┌────────────────┐          │
│  │  Web 应用层    │◄───────►│  业务逻辑层    │          │
│  └────────────────┘         └────────────────┘          │
│  ⚠️ 可被 root 权限攻击者修改代码绕过                       │
│                                    ▲                      │
│                                    │                      │
│  ┌─────────────────────────────────▼──────────────────┐  │
│  │        硬件信任边界 (TPM with Policy)               │  │
│  │  ┌──────────┐  ┌──────────────┐  ┌──────────┐     │  │
│  │  │ 核心密钥 │  │ TPM 时钟+    │  │ 加密引擎 │     │  │
│  │  │          │  │ Policy Engine│  │          │     │  │
│  │  └──────────┘  └──────────────┘  └──────────┘     │  │
│  │  ✅ 不可被应用层代码绕过（需正确配置 Policy）         │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**关键点**：
- 应用层代码可被 root 权限攻击者修改
- TPM Policy 在硬件层强制执行，应用层无法绕过
- 前提：Policy 正确配置且密钥材料不以明文形式离开 TPM

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

**存储安全**：
- ❌ 服务器不存储私钥
- ✅ 私钥仅在生成时显示一次
- ✅ 加密后包含在公钥中
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
  "encrypted_server_url": {
    "ciphertext": "base64_encoded",
    "nonce": "base64_encoded"
  },
  "encrypted_payload": {
    "ciphertext": "base64_encoded",
    "nonce": "base64_encoded"
  },
  "metadata": {
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

加密服务器地址（encrypted_server_url）使用转换密钥派生的密钥加密，可在任何服务器上解密。

加密载荷（encrypted_payload）使用核心密钥参与派生的密钥加密，只能在正确的服务器上解密，解密后包含：
```json
{
  "private_key": "aB3$xY9#mK2p",
  "time_window": {
    "start": "timestamp",
    "end": "timestamp"
  }
}
```

**安全特性**：
- ✅ 使用 AES-256-GCM 认证加密
- ✅ 服务器地址使用转换密钥派生的密钥加密，可在任何地方解密以提示正确地址
- ✅ 时间窗口和私钥使用核心密钥参与派生的密钥加密，仅在正确服务器上可解密
- ✅ 存储转换密钥数量（`transfer_keys_count`）
- ✅ 存储所有转换密钥的哈希（`transfer_keys_hashes`）
- ✅ 转换密钥仅存哈希，不存明文
- ✅ Base64 编码便于传输

**密钥派生机制**：

```python
def derive_url_key_from_transfer_keys(transfer_keys, tpm_time_seed):
    """
    从转换密钥派生服务器地址加密密钥
    
    此密钥不依赖核心密钥，可在任何服务器上使用
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    sorted_keys = sorted(transfer_keys)
    combined_keys = '|'.join(sorted_keys).encode()
    keys_hash = hashlib.sha256(combined_keys).digest()
    
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=keys_hash,
        info=b'kcs-url-encryption'
    )
    
    input_material = combined_keys + tpm_time_seed.to_bytes(8, 'big')
    return kdf.derive(input_material)

def derive_payload_key_from_core_and_transfer(core_key, transfer_keys, tpm_time_seed):
    """
    从核心密钥和转换密钥派生载荷加密密钥
    
    此密钥依赖核心密钥，只能在正确服务器上使用
    """
    import hashlib
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    sorted_keys = sorted(transfer_keys)
    combined_keys = '|'.join(sorted_keys).encode()
    keys_hash = hashlib.sha256(combined_keys).digest()
    
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=keys_hash,
        info=b'kcs-payload-encryption'
    )
    
    input_material = core_key + combined_keys + tpm_time_seed.to_bytes(8, 'big')
    return kdf.derive(input_material)
```

**密钥转换验证流程**：

```python
def convert_key_with_validation(public_key, transfer_keys, current_server_url, tpm):
    """
    密钥转换的完整验证流程
    
    返回格式：
    - 成功：{"success": True, "private_key": "..."}
    - 转换密钥不匹配：{"success": False, "error": "TRANSFER_KEY_MISMATCH"}
    - 服务器地址错误：{"success": False, "error": "SERVER_MISMATCH", "correct_url": "..."}
    - 时间窗口错误：{"success": False, "error": "TIME_OUT_OF_RANGE", "valid_window": {...}}
    """
    import json
    import base64
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # 1. 解析公钥
    public_key_data = json.loads(base64.b64decode(public_key[4:]))
    
    # 2. 验证转换密钥哈希
    stored_hashes = set(public_key_data['metadata']['transfer_keys_hashes'])
    provided_hashes = set(
        hashlib.sha256(key.encode()).hexdigest()
        for key in transfer_keys
    )
    
    if provided_hashes != stored_hashes:
        return {
            "success": False,
            "error": "TRANSFER_KEY_MISMATCH",
            "message": "转换密钥不匹配"
        }
    
    # 3. 解密服务器地址（使用转换密钥派生的密钥，任何服务器都能解密）
    url_key = derive_url_key_from_transfer_keys(
        transfer_keys,
        public_key_data['metadata']['tpm_time_seed']
    )
    
    try:
        aesgcm = AESGCM(url_key)
        nonce = base64.b64decode(public_key_data['encrypted_server_url']['nonce'])
        ciphertext = base64.b64decode(public_key_data['encrypted_server_url']['ciphertext'])
        server_url = aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return {
            "success": False,
            "error": "DECRYPTION_FAILED",
            "message": "解密服务器地址失败"
        }
    
    # 4. 验证服务器地址
    if server_url != current_server_url:
        return {
            "success": False,
            "error": "SERVER_MISMATCH",
            "message": "当前服务器地址不匹配",
            "correct_url": server_url
        }
    
    # 5. 解密载荷（使用核心密钥派生的密钥，只能在正确服务器上解密）
    core_key_material = get_core_key_material_from_tpm(tpm)
    payload_key = derive_payload_key_from_core_and_transfer(
        core_key_material,
        transfer_keys,
        public_key_data['metadata']['tpm_time_seed']
    )
    
    try:
        aesgcm = AESGCM(payload_key)
        nonce = base64.b64decode(public_key_data['encrypted_payload']['nonce'])
        ciphertext = base64.b64decode(public_key_data['encrypted_payload']['ciphertext'])
        
        decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None).decode()
        payload = json.loads(decrypted_payload)
    except Exception:
        return {
            "success": False,
            "error": "PAYLOAD_DECRYPTION_FAILED",
            "message": "载荷解密失败"
        }
    
    # 6. 验证时间窗口
    current_time = get_tpm_time(tpm)
    time_window = payload['time_window']
    
    if not (time_window['start'] <= current_time <= time_window['end']):
        return {
            "success": False,
            "error": "TIME_OUT_OF_RANGE",
            "message": "不在允许的时间范围内",
            "valid_window": time_window,
            "current_time": current_time
        }
    
    # 7. 所有验证通过，返回私钥
    return {
        "success": True,
        "private_key": payload['private_key']
    }
```

**安全性分析**：

核心密钥不可逆推：
- 服务器地址使用仅依赖转换密钥的密钥加密，可在任何服务器上解密
- 时间窗口和私钥使用依赖核心密钥的密钥加密，只能在正确服务器上解密
- 加密密钥通过 HKDF 从核心密钥派生
- HKDF 是单向函数，即使知道输出也无法逆推输入
- 核心密钥存储在 TPM 中，永不导出
- 即使知道：公钥、转换密钥、服务器地址、时间窗口、私钥，也无法反推核心密钥

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

**攻击场景分析（应用层防护）**：

| 攻击方法 | 是否成功 | 原因 |
|---------|---------|------|
| 修改系统时间 | ❌ 失败 | 使用 TPM 时钟，不受影响 |
| 修改公钥中的时间窗口 | ❌ 失败 | 时间窗口通过核心密钥嵌入派生过程，篡改导致解密失败 |
| 克隆 TPM 状态 | ❌ 失败 | TPM 状态不可导出 |
| 回滚 TPM 时钟 | ❌ 失败 | Reset 计数器会改变 |
| 修改代码跳过时间检查 | ⚠️ 应用层成功 | 攻击者修改代码后可直接返回解密后的私钥，应用层无法防护 |

## 5. TPM Policy 强制时间窗口

### 5.1 方案概述

为了对抗"攻击者获得服务器完全控制权限并修改应用代码"的威胁，需要将解密权限下沉到 TPM 硬件边界，使用 TPM Policy 机制强制时间窗口。

**核心思路**：将解密所需的关键材料（如 payload 解密密钥的种子）封装为 TPM sealed object，设置 authPolicy 包含 PolicyCounterTimer 约束。应用层必须通过满足 policy 的 session 才能 unseal 获取密钥材料，TPM 在硬件层验证时间条件。

### 5.2 方案一：Sealed Object + PolicyCounterTimer

**适用场景**：需要防止服务器管理员修改代码绕过时间检查。

**设计原理**：
1. 生成阶段：将 payload 解密密钥的种子（seed）作为敏感数据 seal 到 TPM
2. 创建 sealed object 时设置 authPolicy，包含 PolicyCounterTimer 约束
3. 转换阶段：必须启动 policy session，执行 PolicyCounterTimer 满足时间约束，然后 unseal
4. 如果当前 TPM clock 不在允许范围，PolicyCounterTimer 失败，TPM 拒绝 unseal

**对象创建流程**：

```
1. 计算 policy digest (trial session)
   - StartAuthSession(TRIAL)
   - PolicyCounterTimer(session, operandB=start_tick, offset=0, operation=GREATER_OR_EQUAL)
   - PolicyCounterTimer(session, operandB=end_tick, offset=0, operation=LESS_OR_EQUAL)
   - PolicyGetDigest() -> policyDigest

2. 创建 sealed object
   - Create(parent=SRK, inSensitive=seed, inPublic.authPolicy=policyDigest)
   - Load() -> sealedHandle
   - 持久化或保存 sealed blob

3. 在公钥 metadata 中记录
   - sealed_object_blob (base64)
   - tpm_start_tick, tpm_end_tick
   - policy_type: "PolicyCounterTimer"
```

**运行时使用流程**：

```
1. 解析公钥获取 sealed_object_blob 和时间约束
2. Load sealed object -> sealedHandle
3. 启动 policy session
   - StartAuthSession(POLICY)
   - PolicyCounterTimer(session, operandB=start_tick, offset=0, operation=GREATER_OR_EQUAL)
   - PolicyCounterTimer(session, operandB=end_tick, offset=0, operation=LESS_OR_EQUAL)
4. Unseal(sealedHandle, sessionHandle=policySession)
   - 成功: 获得 seed，派生 payload key，解密私钥
   - 失败: TPM 返回错误码 (如 TPM_RC_POLICY_FAIL)，应用层无法绕过
```

### 5.3 时间窗口表达策略

**策略一：相对时间窗口（推荐）**

直接使用 TPM clock tick 表达时间窗口：

```python
def map_relative_time_window(duration_seconds):
    """
    相对时间窗口：从当前时刻起 N 秒内有效
    
    优点：简单直接，不依赖 UTC 映射
    适用：短期密钥（几小时到几天）
    """
    current_tick = tpm.read_clock().clock
    start_tick = current_tick
    end_tick = current_tick + (duration_seconds * 1000)  # TPM clock 单位为毫秒
    
    return {
        "start_tick": start_tick,
        "end_tick": end_tick,
        "duration_seconds": duration_seconds
    }
```

**策略二：绝对时间窗口（需锚定）**

将 UTC 时间映射到 TPM tick：

```python
def map_absolute_time_window(utc_start, utc_end):
    """
    绝对时间窗口：映射 UTC 时间到 TPM tick
    
    前提：
    1. 系统时间与 NTP 同步
    2. 记录映射锚点 (utc_anchor, tpm_tick_anchor)
    3. 假设 TPM clock 未重置
    
    限制：
    - TPM 重启/重置会使映射失效
    - 需要在生成和转换时都能访问可信的锚点
    """
    import time
    
    # 读取当前锚点
    current_utc = time.time()
    current_tick = tpm.read_clock().clock
    
    # 计算目标 tick (假设 TPM clock 连续递增)
    start_tick = current_tick + ((utc_start - current_utc) * 1000)
    end_tick = current_tick + ((utc_end - current_utc) * 1000)
    
    return {
        "start_tick": start_tick,
        "end_tick": end_tick,
        "utc_start": utc_start,
        "utc_end": utc_end,
        "anchor_utc": current_utc,
        "anchor_tick": current_tick
    }
```

**注意事项**：
- 绝对时间映射需要记录锚点并假设 TPM 未重启
- TPM reset_count 或 restart_count 变化会使锚点失效
- 建议在公钥 metadata 中记录 reset_count 和 restart_count
- 如果检测到计数器变化，应拒绝转换并提示需要重新生成

### 5.4 PolicyCounterTimer 详细说明

TPM 2.0 PolicyCounterTimer 命令允许对 TPM 内部计数器/时钟设置约束：

**支持的操作符**：
- `TPM_EO_EQ`: 等于
- `TPM_EO_NEQ`: 不等于
- `TPM_EO_SIGNED_GT`: 大于（有符号）
- `TPM_EO_UNSIGNED_GT`: 大于（无符号）
- `TPM_EO_SIGNED_LT`: 小于（有符号）
- `TPM_EO_UNSIGNED_LT`: 小于（无符号）
- `TPM_EO_SIGNED_GE`: 大于等于（有符号）
- `TPM_EO_UNSIGNED_GE`: 大于等于（无符号）
- `TPM_EO_SIGNED_LE`: 小于等于（有符号）
- `TPM_EO_UNSIGNED_LE`: 小于等于（无符号）

**时间窗口实现**：需要两个 PolicyCounterTimer 命令组合：
1. `clock >= start_tick` (UNSIGNED_GE)
2. `clock <= end_tick` (UNSIGNED_LE)

**示例（概念级）**：
```bash
# Trial session 计算 digest
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policycountertimer -S session.ctx -L policy.dat \
    --ult=1000000000  # clock < end_tick (示例值)
tpm2_policycountertimer -S session.ctx -L policy.dat \
    --ugt=0  # clock > start_tick (示例值)
POLICY_DIGEST=$(tpm2_policygetdigest -S session.ctx)
tpm2_flushcontext session.ctx

# 创建 sealed object
tpm2_create -C primary.ctx -i seed.dat -u sealed.pub -r sealed.priv \
    -L policy.dat

# 使用时启动 policy session
tpm2_startauthsession -S session.ctx --policy-session
tpm2_policycountertimer -S session.ctx --ult=1000000000 --ugt=0
tpm2_unseal -c sealed.ctx -p session:session.ctx -o seed.dat
```

### 5.5 错误码与审计

**新增错误码**：

| 错误码 | 描述 | HTTP 状态码 |
|--------|------|------------|
| `TIME_POLICY_DENIED` | TPM Policy 时间约束不满足 | 403 |
| `TPM_POLICY_FAILURE` | TPM Policy 验证失败（通用） | 500 |
| `TPM_CLOCK_RESET_DETECTED` | 检测到 TPM 时钟重置，时间锚点失效 | 409 |
| `SEALED_OBJECT_LOAD_FAILED` | 加载 sealed object 失败 | 500 |
| `POLICY_SESSION_FAILED` | 启动或执行 policy session 失败 | 500 |

**审计日志要求**：

记录以下信息（不记录私钥、转换密钥）：
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "action": "KEY_CONVERSION_WITH_POLICY",
  "client_ip": "192.168.1.100",
  "public_key_hash": "sha256:abc123...",
  "policy_type": "PolicyCounterTimer",
  "time_window": {
    "start_tick": 1000000,
    "end_tick": 2000000
  },
  "tpm_current_tick": 1500000,
  "tpm_reset_count": 0,
  "tpm_restart_count": 5,
  "result": "success",
  "error_code": null
}
```

如果失败：
```json
{
  "result": "failure",
  "error_code": "TIME_POLICY_DENIED",
  "tpm_error": "TPM_RC_POLICY_FAIL"
}
```

### 5.6 方案二：Restricted Signing/Decryption Key（高级）

**适用场景**：需要最高安全级别，愿意改造更大。

**设计原理**：
- 让 TPM 直接执行 decrypt/sign 操作，而不是 seal/unseal
- 创建受限密钥（restricted key）并设置 authPolicy
- 应用层调用 TPM_Decrypt/TPM_Sign 时必须满足 policy
- 私钥解密过程完全在 TPM 内完成

**改造成本**：
- 需要重新设计加密流程，使 TPM 密钥直接参与 payload 解密
- API 和数据结构变化较大
- 本文档以方案一为主，方案二仅作为备选参考

### 5.7 残余风险与限制

**PolicyCounterTimer 的限制**：
1. **相对时间 vs 绝对时间**：TPM clock 是相对时间（tick），非 UTC 绝对时间
2. **锚点依赖**：绝对时间窗口需要可信的 UTC-to-tick 映射锚点
3. **TPM 重启影响**：restart_count 增加不影响 clock，但 reset_count 增加会清零 clock
4. **表达能力**：无法直接表达"每天 9:00-17:00"等复杂策略（需应用层预处理或 PolicySigned）

**残余风险**：
1. **物理攻击**：攻击者物理访问 TPM 芯片可能通过硬件攻击提取密钥（极高成本）
2. **固件漏洞**：TPM 固件漏洞可能绕过 policy（需及时更新固件）
3. **时钟操纵**（理论）：某些 TPM 实现允许特权操作修改 clock（需检查 TPM 配置）
4. **Policy 配置错误**：authPolicy 设置不正确导致约束失效（需测试验证）
5. **Sealed object 导出**：如果 sealed object 的父密钥可导出，整个方案失效（必须使用 SRK 等不可导出密钥）

**必要条件清单**（达到不可绕过）：
- ✅ 使用真实 TPM 2.0 硬件（swtpm 仅用于开发测试）
- ✅ Sealed object 的父密钥（如 SRK）设置 FIXEDTPM 和 FIXEDPARENT
- ✅ 应用代码不以明文形式记录或传输 unsealed seed
- ✅ 禁用所有 TPM debug/导出路径
- ✅ 部署环境隔离，防止物理访问
- ✅ Policy digest 计算正确，与 sealed object authPolicy 一致
- ✅ TPM 固件及时更新，修复已知漏洞

### 5.8 替代方案：PolicySigned

对于更复杂的时间策略或需要外部授权的场景，可使用 PolicySigned：
- 由外部授权服务持有签名密钥
- 授权服务根据业务逻辑和时间条件签发 ticket
- TPM 验证签名后允许操作

**优势**：
- 灵活表达任意策略（包括复杂时间规则）
- 支持动态授权和撤销
- 时间验证在授权服务完成，可使用 UTC 时间

**劣势**：
- 需要独立的授权服务
- 增加系统复杂度
- 授权服务成为新的信任边界

本文档主要关注 PolicyCounterTimer 方案，PolicySigned 方案可作为未来扩展方向。

## 6. 攻击场景总结（更新后）

| 攻击方法 | 应用层防护 | TPM Policy 防护 | 最终结果 |
|---------|---------|-----------------|---------|
| 修改系统时间 | ❌ 失败 | ❌ 失败 | ❌ 失败 |
| 修改代码跳过时间检查 | ⚠️ 可绕过 | ❌ 失败 | 配置 Policy 后失败 ✅ |
| 修改公钥中的时间窗口 | ❌ 失败 | ❌ 失败 | ❌ 失败 |
| 克隆 TPM 状态 | ❌ 失败 | ❌ 失败 | ❌ 失败 |
| 回滚 TPM 时钟 | ❌ 失败 | ❌ 失败 | ❌ 失败 |

## 7. 网络通信安全

### 7.1 HTTPS 强制

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

### 7.2 证书管理

- 使用 Let's Encrypt 或商业证书
- 定期自动续期
- 监控证书过期时间
- 使用证书透明度日志

### 7.3 API 安全

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

## 8. 审计与日志

### 8.1 日志记录规范

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

### 8.2 审计日志详细说明

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

def log_key_conversion_with_policy(user_ip, public_key_hash, policy_type, time_window, tpm_info, success, error_code=None):
    """
    记录使用 TPM Policy 的密钥转换操作
    
    记录内容：
    - 时间戳、操作类型、客户端 IP
    - Policy 类型（如 PolicyCounterTimer）
    - 时间窗口参数（tick 范围）
    - TPM 状态（current tick, reset_count, restart_count）
    - 操作结果和错误码
    
    不记录：
    - ❌ 转换密钥
    - ❌ 还原出的私钥
    - ❌ Sealed object 内容
    - ❌ Unsealed seed
    """
    log_level = logging.WARNING if not success else logging.INFO
    audit_logger.log(log_level, json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "action": "KEY_CONVERSION_WITH_POLICY",
        "client_ip": user_ip,
        "public_key_hash": public_key_hash,
        "policy_type": policy_type,
        "time_window": {
            "start_tick": time_window.get('start_tick'),
            "end_tick": time_window.get('end_tick')
        },
        "tpm_current_tick": tpm_info.get('clock'),
        "tpm_reset_count": tpm_info.get('reset_count'),
        "tpm_restart_count": tpm_info.get('restart_count'),
        "tpm_safe": tpm_info.get('safe'),
        "success": success,
        "error_code": error_code
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
        'master_key',
        'sealed_seed',
        'unsealed_seed',
        'payload_key'
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

### 8.3 日志分析和监控

**监控指标**：

- 监控失败的转换尝试（可能的暴力破解）
- 监控 TPM Policy 验证失败次数
- 监控 TPM 时钟重置/重启计数器变化
- 识别异常的生成模式
- 追踪密钥使用统计
- 检测可疑的 IP 地址

### 8.4 安全事件响应

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

## 9. 数据保护

### 9.1 敏感数据处理

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

### 9.2 内存安全

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

## 10. 安全测试

### 10.1 渗透测试检查清单

- [ ] 尝试暴力破解转换密钥
- [ ] 尝试修改系统时间绕过限制
- [ ] 尝试 SQL 注入（如使用数据库）
- [ ] 尝试 XSS 攻击
- [ ] 尝试 CSRF 攻击
- [ ] 尝试中间人攻击
- [ ] 测试速率限制是否生效
- [ ] 测试证书验证
- [ ] 测试错误信息是否泄露敏感信息

### 10.2 安全审计

定期进行：
- 代码审计
- 依赖库漏洞扫描
- 配置审查
- 日志审查
- 渗透测试

## 11. 合规性

### 11.1 数据保护法规

根据使用场景，可能需要遵守：
- GDPR（欧盟）
- CCPA（加利福尼亚）
- 中国《数据安全法》
- 中国《个人信息保护法》

### 11.2 加密标准

- ✅ TPM 2.0：ISO/IEC 11889
- ✅ AES-256：FIPS 197
- ✅ SHA-256：FIPS 180-4
- ✅ TLS 1.2/1.3：RFC 5246/8446

## 12. 安全最佳实践

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
