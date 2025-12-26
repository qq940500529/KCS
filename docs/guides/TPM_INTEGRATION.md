# TPM 集成开发指南

## 1. TPM 2.0 概述

TPM (Trusted Platform Module) 2.0 是一个国际标准的安全加密处理器芯片，提供硬件级别的安全功能。

### 1.1 TPM 的核心特性

- **硬件隔离**：密钥在硬件中生成和存储，不会暴露给操作系统
- **防篡改时钟**：提供独立的时间计数器
- **密钥派生**：支持层级密钥结构
- **密封/解封**：将数据绑定到特定平台状态
- **远程证明**：验证平台完整性

## 2. 开发环境搭建

### 2.1 安装 TPM 2.0 工具栈

#### Ubuntu/Debian

```bash
# 安装 TPM 2.0 TSS (TPM2 Software Stack)
sudo apt-get update
sudo apt-get install -y \
    tpm2-tools \
    tpm2-abrmd \
    libtpm2-pkcs11-1 \
    libtss2-dev \
    libtss2-esys-3.0.2-0

# 安装 TPM 模拟器（用于开发测试）
sudo apt-get install -y libtpms-dev swtpm swtpm-tools
```

#### CentOS/RHEL

```bash
sudo yum install -y tpm2-tools tpm2-abrmd libtss2-dev
```

### 2.2 启动 TPM 模拟器（开发环境）

```bash
# 创建 TPM 状态目录
mkdir -p /tmp/tpm_state

# 启动 swtpm 模拟器
swtpm socket --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --tpm2 \
    --flags not-need-init &

# 设置环境变量
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"

# 测试连接
tpm2_getcap properties-fixed
```

### 2.3 Python 开发环境

```bash
# 安装 Python TPM 库
pip install tpm2-pytss

# 或使用 tpm2-tools 的命令行接口
pip install subprocess
```

### 2.4 Go 开发环境

```bash
# 安装 Go TPM 库
go get github.com/google/go-tpm/tpm2
go get github.com/google/go-tpm/tpmutil
```

## 3. TPM 基础操作

### 3.1 检查 TPM 可用性

#### Python 示例

```python
from tpm2_pytss import ESAPI, TPM2Error

def check_tpm_availability():
    try:
        esapi = ESAPI()
        # 获取 TPM 属性
        caps = esapi.get_capability(TPM2_CAP_TPM_PROPERTIES, 
                                     TPM2_PT_FAMILY_INDICATOR, 1)
        print(f"TPM Family: {caps}")
        return True
    except TPM2Error as e:
        print(f"TPM not available: {e}")
        return False
```

#### 命令行示例

```bash
# 检查 TPM 版本
tpm2_getcap properties-fixed

# 检查 TPM 算法支持
tpm2_getcap algorithms
```

### 3.2 生成核心密钥

#### 3.2.1 使用 Primary Key

```bash
# 创建 Primary Key（所有者层级）
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

# 将 Primary Key 持久化到 NV
tpm2_evictcontrol -C o -c primary.ctx 0x81010001
```

#### 3.2.2 Python 示例

```python
from tpm2_pytss import *

def create_core_key(esapi, server_url, salt):
    """
    创建绑定到硬件的核心密钥
    """
    # 读取 Endorsement Key (硬件特征)
    ek_handle = esapi.create_primary(
        TPM2_RH_ENDORSEMENT,
        public_template=TPM2B_PUBLIC(
            publicArea=TPMT_PUBLIC(
                type=TPM2_ALG_RSA,
                nameAlg=TPM2_ALG_SHA256,
                objectAttributes=TPMA_OBJECT_FIXEDTPM | 
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                TPMA_OBJECT_ADMINWITHPOLICY |
                                TPMA_OBJECT_RESTRICTED |
                                TPMA_OBJECT_DECRYPT,
                # ... 其他参数
            )
        )
    )
    
    # 创建核心密钥（基于 EK + URL + Salt）
    auth_data = f"{server_url}:{salt}".encode()
    
    core_key_handle = esapi.create_primary(
        TPM2_RH_OWNER,
        sensitive_data=TPM2B_SENSITIVE_CREATE(
            sensitive=TPMS_SENSITIVE_CREATE(
                userAuth=TPM2B_AUTH(buffer=auth_data)
            )
        ),
        public_template=TPM2B_PUBLIC(
            publicArea=TPMT_PUBLIC(
                type=TPM2_ALG_SYMCIPHER,
                nameAlg=TPM2_ALG_SHA256,
                objectAttributes=TPMA_OBJECT_FIXEDTPM | 
                                TPMA_OBJECT_FIXEDPARENT |
                                TPMA_OBJECT_USERWITHAUTH,
                # ... 其他参数
            )
        )
    )
    
    # 持久化到 NV
    persistent_handle = 0x81010001
    esapi.evict_control(
        TPM2_RH_OWNER,
        core_key_handle,
        persistent_handle
    )
    
    return persistent_handle
```

### 3.3 读取 TPM 时间

#### 命令行示例

```bash
# 读取 TPM 时钟
tpm2_readclock
```

#### Python 示例

```python
def get_tpm_time(esapi):
    """
    读取 TPM 内部时间
    """
    time_info = esapi.read_clock()
    
    return {
        "clock": time_info.clock,
        "reset_count": time_info.resetCount,
        "restart_count": time_info.restartCount,
        "safe": time_info.safe
    }
```

### 3.4 密钥派生函数 (KDF) - 支持多转换密钥

```python
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_master_key(core_key_material, transfer_keys, tpm_time_seed):
    """
    派生主密钥，用于加密私钥
    支持任意数量的转换密钥组合，输入顺序无关
    
    Args:
        core_key_material: 核心密钥材料（从 TPM 获取）
        transfer_keys: 转换密钥列表（所有转换密钥，至少 1 个）
        tpm_time_seed: TPM 时间种子
    
    Returns:
        派生的主密钥
    """
    # 1. 对所有转换密钥进行排序（确保顺序无关）
    sorted_keys = sorted(transfer_keys)
    
    # 2. 组合所有转换密钥
    combined_keys = '|'.join(sorted_keys).encode()
    
    # 3. 计算组合密钥的哈希
    keys_hash = hashlib.sha256(combined_keys).digest()
    
    # 4. 组合输入
    info = f"KCS-v1-{tpm_time_seed}-{len(transfer_keys)}".encode()
    
    # 5. 使用 HKDF 派生密钥
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=keys_hash,  # 使用所有密钥的哈希作为盐
        info=info,
        backend=default_backend()
    )
    
    master_key = hkdf.derive(core_key_material)
    return master_key

def derive_master_key_alternative(core_key_material, transfer_keys, tpm_time_seed):
    """
    替代方案：为每个转换密钥派生子密钥，然后组合
    这种方式更适合严格的多方授权场景
    支持任意数量的转换密钥，输入顺序无关
    
    Args:
        core_key_material: 核心密钥材料（从 TPM 获取）
        transfer_keys: 转换密钥列表（至少 1 个）
        tpm_time_seed: TPM 时间种子
    
    Returns:
        派生的主密钥
    """
    sub_keys = []
    
    # 为每个转换密钥派生一个子密钥
    for i, transfer_key in enumerate(transfer_keys):
        info = f"KCS-v1-{tpm_time_seed}-key-{i}".encode()
        salt = transfer_key.encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        
        sub_key = hkdf.derive(core_key_material)
        sub_keys.append(sub_key)
    
    # 使用 XOR 组合所有子密钥
    master_key = sub_keys[0]
    for sub_key in sub_keys[1:]:
        master_key = bytes(a ^ b for a, b in zip(master_key, sub_key))
    
    return master_key
```

**注意**：两种方法都支持任意数量的转换密钥，且输入顺序无关。

### 3.5 使用 TPM 加密/解密

#### Python 示例

```python
def tpm_encrypt(esapi, key_handle, plaintext):
    """
    使用 TPM 密钥加密数据
    """
    cipher = esapi.encrypt_decrypt(
        key_handle,
        decrypt=False,
        mode=TPM2_ALG_CFB,
        iv=TPM2B_IV(buffer=b'\x00' * 16),
        data=TPM2B_MAX_BUFFER(buffer=plaintext)
    )
    return cipher.buffer

def tpm_decrypt(esapi, key_handle, ciphertext):
    """
    使用 TPM 密钥解密数据
    """
    plaintext = esapi.encrypt_decrypt(
        key_handle,
        decrypt=True,
        mode=TPM2_ALG_CFB,
        iv=TPM2B_IV(buffer=b'\x00' * 16),
        data=TPM2B_MAX_BUFFER(buffer=ciphertext)
    )
    return plaintext.buffer
```

## 4. TPM Policy 机制

TPM Policy 可以实现基于条件的密钥使用控制。当需要对抗服务器代码被修改的威胁时，TPM Policy 是关键防护机制。

### 4.1 Policy 基础概念

**Policy Session**：一种特殊的授权 session，通过执行一系列 policy 命令构建授权条件。

**Policy Digest**：对所有 policy 命令序列的哈希摘要，作为对象的 authPolicy 属性。

**使用流程**：
1. Trial Session：计算 policy digest（不实际执行授权）
2. 创建对象时设置 authPolicy = policy digest
3. Policy Session：运行时重新执行相同的 policy 命令序列
4. TPM 验证 policy digest 匹配后允许操作

### 4.2 时间策略简化示例（仅供理解）

```python
def create_time_bound_key_simple(esapi, start_time, end_time):
    """
    创建时间绑定的密钥（简化示例，仅说明概念）
    
    实际实现见下文第 6 节完整指南
    """
    # 创建 Policy Session
    session = esapi.start_auth_session(
        TPM2_SE_POLICY,
        TPM2_ALG_SHA256
    )
    
    # 设置时间策略
    esapi.policy_command_code(session, TPM2_CC_Unseal)
    
    # 获取当前 TPM 时间
    current_time = esapi.read_clock()
    
    # 计算时间范围
    start_tick = start_time  # 需要转换为 TPM tick
    end_tick = end_time
    
    # 创建时间窗口策略
    # 注意：TPM 2.0 的时间策略需要使用 PolicyOR 或 PolicyCounterTimer
    # 这里是简化示例
    
    # 创建密钥时附加 Policy Digest
    policy_digest = esapi.policy_get_digest(session)
    
    # 创建对象时使用 authPolicy
    key = esapi.create(
        parent_handle,
        in_sensitive=TPM2B_SENSITIVE_CREATE(),
        in_public=TPM2B_PUBLIC(
            publicArea=TPMT_PUBLIC(
                authPolicy=policy_digest,
                # ... 其他参数
            )
        )
    )
    
    return key
```

## 5. 实际集成示例

### 5.1 完整的密钥生成流程

```python
class TPMKeyManager:
    def __init__(self):
        self.esapi = ESAPI()
        self.core_key_handle = 0x81010001
    
    def generate_key_set(self, private_key, transfer_keys, 
                         time_window, server_url):
        """
        生成完整的密钥集（支持任意数量的转换密钥）
        
        Args:
            private_key: 私钥字符串
            transfer_keys: 转换密钥列表（至少 1 个，无上限）
            time_window: 时间窗口字典
            server_url: 服务器 URL
        
        Returns:
            公钥字符串
        """
        import json
        import base64
        import hashlib
        import os
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # 1. 获取 TPM 时间种子
        tpm_time = self.get_tpm_time()
        
        # 2. 从 TPM 获取核心密钥材料
        core_key_material = self._get_core_key_material()
        
        # 3. 派生服务器地址加密密钥（不依赖核心密钥）
        url_key = self._derive_url_key(transfer_keys, tpm_time["clock"])
        
        # 4. 加密服务器地址
        aesgcm = AESGCM(url_key)
        url_nonce = os.urandom(12)
        url_ciphertext = aesgcm.encrypt(url_nonce, server_url.encode(), None)
        
        # 5. 派生载荷加密密钥（依赖核心密钥）
        payload_key = self._derive_payload_key(
            core_key_material,
            transfer_keys,
            tpm_time["clock"]
        )
        
        # 6. 构建并加密载荷
        payload = {
            "private_key": private_key,
            "time_window": time_window
        }
        payload_json = json.dumps(payload)
        
        aesgcm = AESGCM(payload_key)
        payload_nonce = os.urandom(12)
        payload_ciphertext = aesgcm.encrypt(payload_nonce, payload_json.encode(), None)
        
        # 7. 计算每个转换密钥的哈希
        transfer_keys_hashes = [
            hashlib.sha256(key.encode()).hexdigest()
            for key in transfer_keys
        ]
        
        # 8. 生成公钥
        public_key_data = {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "encrypted_server_url": {
                "ciphertext": base64.b64encode(url_ciphertext).decode(),
                "nonce": base64.b64encode(url_nonce).decode()
            },
            "encrypted_payload": {
                "ciphertext": base64.b64encode(payload_ciphertext).decode(),
                "nonce": base64.b64encode(payload_nonce).decode()
            },
            "metadata": {
                "tpm_time_seed": tpm_time["clock"],
                "transfer_keys_count": len(transfer_keys),
                "transfer_keys_hashes": transfer_keys_hashes,
                "created_at": tpm_time["clock"]
            }
        }
        
        public_key = "PUB_" + base64.b64encode(
            json.dumps(public_key_data).encode()
        ).decode()
        
        return public_key
    
    def convert_key(self, public_key, transfer_keys, current_server_url):
        """
        转换公钥为私钥（支持任意数量转换密钥验证，输入顺序无关）
        
        Args:
            public_key: 公钥字符串
            transfer_keys: 用户提供的转换密钥列表（顺序可任意）
            current_server_url: 当前服务器地址
        
        Returns:
            字典格式的结果，包含成功状态和相关信息
        
        Raises:
            ValueError: 转换密钥验证失败
        """
        import json
        import base64
        import hashlib
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # 1. 解析公钥
        public_key_data = json.loads(
            base64.b64decode(public_key[4:])
        )
        
        # 2. 验证转换密钥数量
        required_count = public_key_data["metadata"]["transfer_keys_count"]
        provided_count = len(transfer_keys)
        
        if provided_count != required_count:
            raise ValueError(
                f"需要 {required_count} 个转换密钥，但只提供了 {provided_count} 个"
            )
        
        # 3. 验证每个转换密钥的哈希（顺序无关，使用集合比较）
        stored_hashes = set(public_key_data["metadata"]["transfer_keys_hashes"])
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
        
        # 4. 解密服务器地址（使用转换密钥派生的密钥）
        url_key = self._derive_url_key(
            transfer_keys,
            public_key_data["metadata"]["tpm_time_seed"]
        )
        
        try:
            aesgcm = AESGCM(url_key)
            nonce = base64.b64decode(public_key_data["encrypted_server_url"]["nonce"])
            ciphertext = base64.b64decode(public_key_data["encrypted_server_url"]["ciphertext"])
            server_url = aesgcm.decrypt(nonce, ciphertext, None).decode()
        except Exception:
            return {
                "success": False,
                "error": "URL_DECRYPTION_FAILED",
                "message": "解密服务器地址失败"
            }
        
        # 5. 验证服务器地址
        if server_url != current_server_url:
            return {
                "success": False,
                "error": "SERVER_MISMATCH",
                "message": "当前服务器地址不匹配",
                "correct_url": server_url
            }
        
        # 6. 从TPM获取核心密钥并派生载荷加密密钥
        core_key_material = self._get_core_key_material()
        payload_key = self._derive_payload_key(
            core_key_material,
            transfer_keys,
            public_key_data["metadata"]["tpm_time_seed"]
        )
        
        # 7. 解密载荷
        try:
            aesgcm = AESGCM(payload_key)
            nonce = base64.b64decode(public_key_data["encrypted_payload"]["nonce"])
            ciphertext = base64.b64decode(public_key_data["encrypted_payload"]["ciphertext"])
            
            payload_json = aesgcm.decrypt(nonce, ciphertext, None).decode()
            payload = json.loads(payload_json)
        except Exception:
            return {
                "success": False,
                "error": "PAYLOAD_DECRYPTION_FAILED",
                "message": "载荷解密失败"
            }
        
        # 8. 验证时间窗口
        current_time = self.get_tpm_time()
        time_window = payload["time_window"]
        
        if not (time_window['start'] <= current_time['clock'] <= time_window['end']):
            return {
                "success": False,
                "error": "TIME_OUT_OF_RANGE",
                "message": "不在允许的时间范围内",
                "valid_window": time_window,
                "current_time": current_time['clock']
            }
        
        # 9. 所有验证通过，返回私钥
        return {
            "success": True,
            "private_key": payload["private_key"]
        }
    
    def _derive_url_key(self, transfer_keys, tpm_time_seed):
        """
        派生服务器地址加密密钥（不依赖核心密钥）
        支持任意数量的转换密钥，输入顺序无关
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import hashlib
        
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
    
    def _derive_payload_key(self, core_key_material, transfer_keys, tpm_time_seed):
        """
        派生载荷加密密钥（依赖核心密钥）
        支持任意数量的转换密钥，输入顺序无关
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import hashlib
        
        sorted_keys = sorted(transfer_keys)
        combined_keys = '|'.join(sorted_keys).encode()
        keys_hash = hashlib.sha256(combined_keys).digest()
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=keys_hash,
            info=b'kcs-payload-encryption'
        )
        
        input_material = core_key_material + combined_keys + tpm_time_seed.to_bytes(8, 'big')
        return kdf.derive(input_material)
    
    def _get_core_key_material(self):
        """
        从 TPM 获取核心密钥材料（不导出密钥本身）
        """
        # 使用 TPM 的 HMAC 功能生成密钥材料
        # 这样密钥永远不会离开 TPM
        result = self.esapi.hmac(
            self.core_key_handle,
            buffer=TPM2B_MAX_BUFFER(buffer=b"KCS-core-key-material"),
            hashAlg=TPM2_ALG_SHA256
        )
        return result.buffer
    
    def get_tpm_time(self):
        """
        读取 TPM 时间
        """
        time_info = self.esapi.read_clock()
        return {
            "clock": time_info.clock,
            "reset_count": time_info.resetCount,
            "restart_count": time_info.restartCount
        }
```

## 6. TPM Policy 时间窗口强制

### 6.1 方案概述

为了防止攻击者修改应用代码绕过时间检查，需要使用 TPM Policy（PolicyCounterTimer）在硬件层强制时间窗口。

**核心思路**：
- 将 payload 解密密钥的 seed 封装为 sealed object
- 设置 authPolicy 包含 PolicyCounterTimer 约束
- 运行时必须满足 policy session 才能 unseal
- TPM 在硬件层验证时间条件，应用代码无法绕过

### 6.2 完整实现流程

#### 步骤 1：计算 Policy Digest（Trial Session）

使用 trial session 计算 policy digest，不实际执行授权：

```python
def calculate_policy_digest_for_time_window(esapi, start_tick, end_tick):
    """
    计算时间窗口的 policy digest
    
    Args:
        esapi: TPM ESAPI 实例
        start_tick: 开始时间（TPM tick）
        end_tick: 结束时间（TPM tick）
    
    Returns:
        policy_digest: 用于创建 sealed object 的 authPolicy
    """
    from tpm2_pytss import *
    
    # 1. 启动 trial session
    trial_session = esapi.start_auth_session(
        tpm_key=ESYS_TR_NONE,
        bind=ESYS_TR_NONE,
        session_type=TPM2_SE_TRIAL,
        symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG_NULL),
        auth_hash=TPM2_ALG_SHA256
    )
    
    try:
        # 2. 执行 PolicyCounterTimer 命令
        # 条件 1: clock >= start_tick
        operand_start = start_tick.to_bytes(8, 'big')
        esapi.policy_counter_timer(
            policy_session=trial_session,
            operand_b=TPM2B_OPERAND(buffer=operand_start),
            offset=0,  # offset 0 表示使用 clock
            operation=TPM2_EO_UNSIGNED_GE  # Greater or Equal
        )
        
        # 条件 2: clock <= end_tick
        operand_end = end_tick.to_bytes(8, 'big')
        esapi.policy_counter_timer(
            policy_session=trial_session,
            operand_b=TPM2B_OPERAND(buffer=operand_end),
            offset=0,
            operation=TPM2_EO_UNSIGNED_LE  # Less or Equal
        )
        
        # 3. 获取 policy digest
        policy_digest = esapi.policy_get_digest(trial_session)
        
        return policy_digest.buffer
    
    finally:
        # 清理 session
        esapi.flush_context(trial_session)
```

**使用 tpm2-tools 命令行等价操作**：
```bash
# 启动 trial session
tpm2_startauthsession -S trial.ctx --policy-session

# 添加 PolicyCounterTimer 约束
# 注意：offset 0 = clock, 1-7 表示其他字段
tpm2_policycountertimer -S trial.ctx -L policy.dat \
    --uge=${START_TICK}  # Unsigned Greater or Equal
tpm2_policycountertimer -S trial.ctx -L policy.dat \
    --ule=${END_TICK}    # Unsigned Less or Equal

# 获取 policy digest
POLICY_DIGEST=$(tpm2_policygetdigest -S trial.ctx | cut -d: -f2)

# 清理
tpm2_flushcontext trial.ctx
```

#### 步骤 2：创建 Sealed Object

使用计算出的 policy digest 创建 sealed object：

```python
def create_sealed_object_with_time_policy(esapi, srk_handle, seed, policy_digest):
    """
    创建带时间策略的 sealed object
    
    Args:
        esapi: TPM ESAPI 实例
        srk_handle: Storage Root Key 句柄（父密钥）
        seed: 要封装的敏感数据（如 payload 解密种子）
        policy_digest: 从 trial session 计算的 digest
    
    Returns:
        sealed_public: 公开部分（可存储在公钥中）
        sealed_private: 私有部分（加密的，可存储在公钥中）
    """
    from tpm2_pytss import *
    
    # 构建 in_public 模板
    in_public = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG_KEYEDHASH,
            nameAlg=TPM2_ALG_SHA256,
            objectAttributes=(
                TPMA_OBJECT_FIXEDTPM |
                TPMA_OBJECT_FIXEDPARENT |
                TPMA_OBJECT_USERWITHAUTH |
                TPMA_OBJECT_NO_DA  # 不受字典攻击保护影响
            ),
            authPolicy=TPM2B_DIGEST(buffer=policy_digest),
            parameters=TPMU_PUBLIC_PARMS(
                keyedHashDetail=TPMS_KEYEDHASH_PARMS(
                    scheme=TPMT_KEYEDHASH_SCHEME(
                        scheme=TPM2_ALG_NULL
                    )
                )
            )
        )
    )
    
    # 构建 in_sensitive（敏感数据）
    in_sensitive = TPM2B_SENSITIVE_CREATE(
        sensitive=TPMS_SENSITIVE_CREATE(
            userAuth=TPM2B_AUTH(buffer=b""),  # 空密码
            data=TPM2B_SENSITIVE_DATA(buffer=seed)
        )
    )
    
    # 创建 sealed object
    out_private, out_public, _, _, _ = esapi.create(
        parent_handle=srk_handle,
        in_sensitive=in_sensitive,
        in_public=in_public
    )
    
    return out_public, out_private
```

**使用 tpm2-tools 命令行等价操作**：
```bash
# 将 seed 写入文件
echo -n "${SEED}" > seed.dat

# 创建 sealed object
tpm2_create -C ${SRK_HANDLE} \
    -i seed.dat \
    -u sealed.pub \
    -r sealed.priv \
    -L policy.dat \
    -a "fixedtpm|fixedparent|noda"

# sealed.pub 和 sealed.priv 可存储在公钥 metadata 中（base64 编码）
```

#### 步骤 3：在公钥 Metadata 中记录

修改公钥结构，添加 sealed object 和时间策略信息：

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "encrypted_server_url": { "ciphertext": "...", "nonce": "..." },
  "encrypted_payload": { "ciphertext": "...", "nonce": "..." },
  "metadata": {
    "tpm_time_seed": 1234567890,
    "transfer_keys_count": 2,
    "transfer_keys_hashes": ["sha256:...", "sha256:..."],
    "created_at": "timestamp",
    "tpm_policy": {
      "enabled": true,
      "type": "PolicyCounterTimer",
      "sealed_object": {
        "public": "base64_encoded_sealed_pub",
        "private": "base64_encoded_sealed_priv"
      },
      "time_window": {
        "start_tick": 1000000,
        "end_tick": 2000000
      },
      "tpm_state_snapshot": {
        "reset_count": 0,
        "restart_count": 5
      }
    }
  }
}
```

#### 步骤 4：运行时使用（Unseal）

在密钥转换时，加载 sealed object 并通过 policy session unseal：

```python
def unseal_with_time_policy(esapi, srk_handle, sealed_public, sealed_private, 
                            start_tick, end_tick):
    """
    通过 policy session unseal sealed object
    
    Args:
        esapi: TPM ESAPI 实例
        srk_handle: Storage Root Key 句柄
        sealed_public: sealed object 公开部分
        sealed_private: sealed object 私有部分
        start_tick: 开始时间（TPM tick）
        end_tick: 结束时间（TPM tick）
    
    Returns:
        seed: unsealed 的敏感数据
    
    Raises:
        TPM2Error: 如果当前时间不在窗口内，TPM 返回 TPM_RC_POLICY_FAIL
    """
    from tpm2_pytss import *
    
    # 1. 加载 sealed object
    sealed_handle = esapi.load(
        parent_handle=srk_handle,
        in_private=sealed_private,
        in_public=sealed_public
    )
    
    try:
        # 2. 启动 policy session（非 trial）
        policy_session = esapi.start_auth_session(
            tpm_key=ESYS_TR_NONE,
            bind=ESYS_TR_NONE,
            session_type=TPM2_SE_POLICY,
            symmetric=TPMT_SYM_DEF(algorithm=TPM2_ALG_NULL),
            auth_hash=TPM2_ALG_SHA256
        )
        
        try:
            # 3. 执行与创建时相同的 policy 命令序列
            operand_start = start_tick.to_bytes(8, 'big')
            esapi.policy_counter_timer(
                policy_session=policy_session,
                operand_b=TPM2B_OPERAND(buffer=operand_start),
                offset=0,
                operation=TPM2_EO_UNSIGNED_GE
            )
            
            operand_end = end_tick.to_bytes(8, 'big')
            esapi.policy_counter_timer(
                policy_session=policy_session,
                operand_b=TPM2B_OPERAND(buffer=operand_end),
                offset=0,
                operation=TPM2_EO_UNSIGNED_LE
            )
            
            # 4. Unseal（使用 policy session 作为授权）
            unsealed = esapi.unseal(
                item_handle=sealed_handle,
                session1=policy_session
            )
            
            return unsealed.buffer
        
        finally:
            esapi.flush_context(policy_session)
    
    finally:
        esapi.flush_context(sealed_handle)
```

**使用 tpm2-tools 命令行等价操作**：
```bash
# 加载 sealed object
tpm2_load -C ${SRK_HANDLE} -u sealed.pub -r sealed.priv -c sealed.ctx

# 启动 policy session
tpm2_startauthsession -S session.ctx --policy-session

# 执行 PolicyCounterTimer（必须与创建时一致）
tpm2_policycountertimer -S session.ctx --uge=${START_TICK}
tpm2_policycountertimer -S session.ctx --ule=${END_TICK}

# Unseal（如果时间不在窗口内，TPM 返回错误）
tpm2_unseal -c sealed.ctx -p session:session.ctx -o unsealed_seed.dat

# 清理
tpm2_flushcontext session.ctx
tpm2_flushcontext sealed.ctx
```

### 6.3 完整集成到 KCS 系统

#### 生成阶段修改

```python
def generate_key_with_tpm_policy(esapi, srk_handle, private_key, transfer_keys,
                                 time_window_utc, server_url):
    """
    生成带 TPM Policy 的密钥集
    
    时间窗口策略：相对时间窗口（推荐）
    """
    import json
    import base64
    import hashlib
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # 1. 获取当前 TPM 状态
    time_info = esapi.read_clock()
    current_tick = time_info.clock
    reset_count = time_info.resetCount
    restart_count = time_info.restartCount
    
    # 2. 计算时间窗口（相对）
    duration_seconds = (time_window_utc['end'] - time_window_utc['start'])
    start_tick = current_tick
    end_tick = current_tick + (duration_seconds * 1000)  # TPM tick 单位为毫秒
    
    # 3. 生成 payload 解密 seed
    seed = os.urandom(32)
    
    # 4. 计算 policy digest
    policy_digest = calculate_policy_digest_for_time_window(
        esapi, start_tick, end_tick
    )
    
    # 5. 创建 sealed object
    sealed_public, sealed_private = create_sealed_object_with_time_policy(
        esapi, srk_handle, seed, policy_digest
    )
    
    # 6. 使用 seed 派生 payload key 并加密私钥和时间窗口
    payload_key = hashlib.sha256(seed + b"payload-key").digest()
    payload = {
        "private_key": private_key,
        "time_window": time_window_utc
    }
    payload_json = json.dumps(payload)
    
    aesgcm = AESGCM(payload_key)
    payload_nonce = os.urandom(12)
    payload_ciphertext = aesgcm.encrypt(payload_nonce, payload_json.encode(), None)
    
    # 7. 加密服务器地址（使用转换密钥派生，与原方案一致）
    url_key = derive_url_key_from_transfer_keys(transfer_keys, current_tick)
    url_nonce = os.urandom(12)
    url_ciphertext = AESGCM(url_key).encrypt(url_nonce, server_url.encode(), None)
    
    # 8. 构建公钥
    public_key_data = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "encrypted_server_url": {
            "ciphertext": base64.b64encode(url_ciphertext).decode(),
            "nonce": base64.b64encode(url_nonce).decode()
        },
        "encrypted_payload": {
            "ciphertext": base64.b64encode(payload_ciphertext).decode(),
            "nonce": base64.b64encode(payload_nonce).decode()
        },
        "metadata": {
            "tpm_time_seed": current_tick,
            "transfer_keys_count": len(transfer_keys),
            "transfer_keys_hashes": [
                hashlib.sha256(k.encode()).hexdigest() for k in transfer_keys
            ],
            "created_at": current_tick,
            "tpm_policy": {
                "enabled": True,
                "type": "PolicyCounterTimer",
                "sealed_object": {
                    "public": base64.b64encode(sealed_public).decode(),
                    "private": base64.b64encode(sealed_private).decode()
                },
                "time_window": {
                    "start_tick": start_tick,
                    "end_tick": end_tick
                },
                "tpm_state_snapshot": {
                    "reset_count": reset_count,
                    "restart_count": restart_count
                }
            }
        }
    }
    
    public_key = "PUB_" + base64.b64encode(
        json.dumps(public_key_data).encode()
    ).decode()
    
    return public_key
```

#### 转换阶段修改

```python
def convert_key_with_tpm_policy(esapi, srk_handle, public_key, transfer_keys,
                                current_server_url):
    """
    使用 TPM Policy 转换密钥
    
    返回：
    - success: bool
    - private_key: str (如果成功)
    - error_code: str (如果失败)
    """
    import json
    import base64
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # 1. 解析公钥
    public_key_data = json.loads(base64.b64decode(public_key[4:]))
    
    # 2. 检查是否启用了 TPM Policy
    if not public_key_data['metadata'].get('tpm_policy', {}).get('enabled'):
        return {
            "success": False,
            "error_code": "TPM_POLICY_NOT_ENABLED"
        }
    
    policy_info = public_key_data['metadata']['tpm_policy']
    
    # 3. 验证 TPM 状态（检查 reset_count）
    current_time_info = esapi.read_clock()
    stored_reset_count = policy_info['tpm_state_snapshot']['reset_count']
    
    if current_time_info.resetCount != stored_reset_count:
        return {
            "success": False,
            "error_code": "TPM_CLOCK_RESET_DETECTED",
            "message": "TPM 时钟已重置，时间锚点失效"
        }
    
    # 4. 验证转换密钥（与原方案一致）
    stored_hashes = set(public_key_data['metadata']['transfer_keys_hashes'])
    provided_hashes = set(
        hashlib.sha256(k.encode()).hexdigest() for k in transfer_keys
    )
    
    if provided_hashes != stored_hashes:
        return {
            "success": False,
            "error_code": "TRANSFER_KEY_MISMATCH"
        }
    
    # 5. 解密服务器地址并验证
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
            "error_code": "URL_DECRYPTION_FAILED"
        }
    
    if server_url != current_server_url:
        return {
            "success": False,
            "error_code": "SERVER_MISMATCH",
            "correct_url": server_url
        }
    
    # 6. 通过 TPM Policy unseal seed
    sealed_public = base64.b64decode(policy_info['sealed_object']['public'])
    sealed_private = base64.b64decode(policy_info['sealed_object']['private'])
    start_tick = policy_info['time_window']['start_tick']
    end_tick = policy_info['time_window']['end_tick']
    
    try:
        seed = unseal_with_time_policy(
            esapi, srk_handle, sealed_public, sealed_private,
            start_tick, end_tick
        )
    except TPM2Error as e:
        # TPM 返回错误，可能是时间不在窗口内
        if "TPM_RC_POLICY_FAIL" in str(e):
            return {
                "success": False,
                "error_code": "TIME_POLICY_DENIED",
                "message": "TPM Policy 时间约束不满足",
                "current_tick": current_time_info.clock,
                "allowed_window": {
                    "start_tick": start_tick,
                    "end_tick": end_tick
                }
            }
        else:
            return {
                "success": False,
                "error_code": "TPM_POLICY_FAILURE",
                "tpm_error": str(e)
            }
    
    # 7. 使用 seed 派生 payload key 并解密
    payload_key = hashlib.sha256(seed + b"payload-key").digest()
    
    try:
        aesgcm = AESGCM(payload_key)
        nonce = base64.b64decode(public_key_data['encrypted_payload']['nonce'])
        ciphertext = base64.b64decode(public_key_data['encrypted_payload']['ciphertext'])
        
        payload_json = aesgcm.decrypt(nonce, ciphertext, None).decode()
        payload = json.loads(payload_json)
    except Exception:
        return {
            "success": False,
            "error_code": "PAYLOAD_DECRYPTION_FAILED"
        }
    
    # 8. 成功，返回私钥
    return {
        "success": True,
        "private_key": payload['private_key'],
        "time_window": payload['time_window']
    }
```

### 6.4 错误处理和审计

在 API 层添加错误处理：

```python
@app.post("/api/v1/keys/convert")
async def convert_keys_api(request: KeyConversionRequest):
    """
    密钥转换 API（支持 TPM Policy）
    """
    import logging
    
    result = convert_key_with_tpm_policy(
        esapi, srk_handle, 
        request.public_key,
        request.transfer_keys,
        get_current_server_url()
    )
    
    # 记录审计日志
    if result.get('error_code') == 'TIME_POLICY_DENIED':
        logging.warning(
            f"TPM Policy time denied: client={request.client.host}, "
            f"current_tick={result.get('current_tick')}, "
            f"window={result.get('allowed_window')}"
        )
    
    if not result['success']:
        return {
            "success": False,
            "error": {
                "code": result['error_code'],
                "message": result.get('message', 'Conversion failed'),
                "details": {
                    k: v for k, v in result.items() 
                    if k not in ['success', 'error_code', 'message']
                }
            }
        }
    
    return {
        "success": True,
        "data": {
            "private_key": result['private_key'],
            "time_window": result['time_window']
        }
    }
```

### 6.5 测试和验证

#### 测试用例 1：时间窗口内转换

```python
def test_convert_within_time_window():
    # 生成密钥（时间窗口：未来 1 小时）
    public_key = generate_key_with_tpm_policy(
        esapi, srk_handle,
        private_key="TestKey123!",
        transfer_keys=["TK-abc123"],
        time_window_utc={
            "start": time.time(),
            "end": time.time() + 3600
        },
        server_url="https://kcs.example.com"
    )
    
    # 立即转换（应该成功）
    result = convert_key_with_tpm_policy(
        esapi, srk_handle,
        public_key,
        ["TK-abc123"],
        "https://kcs.example.com"
    )
    
    assert result['success'] == True
    assert result['private_key'] == "TestKey123!"
```

#### 测试用例 2：时间窗口外转换

```python
def test_convert_outside_time_window():
    # 生成密钥（时间窗口：过去 1 小时）
    public_key = generate_key_with_tpm_policy(
        esapi, srk_handle,
        private_key="TestKey123!",
        transfer_keys=["TK-abc123"],
        time_window_utc={
            "start": time.time() - 7200,
            "end": time.time() - 3600
        },
        server_url="https://kcs.example.com"
    )
    
    # 尝试转换（应该失败）
    result = convert_key_with_tpm_policy(
        esapi, srk_handle,
        public_key,
        ["TK-abc123"],
        "https://kcs.example.com"
    )
    
    assert result['success'] == False
    assert result['error_code'] == "TIME_POLICY_DENIED"
```

#### 测试用例 3：修改应用代码尝试绕过

```python
def test_bypass_attempt():
    """
    模拟攻击者修改代码尝试绕过时间检查
    
    即使跳过时间验证，TPM 仍会在 unseal 时拒绝操作
    """
    # 生成密钥（时间窗口：过去）
    public_key = generate_key_with_tpm_policy(...)
    
    # 攻击者修改代码，直接调用 unseal（模拟）
    sealed_public = extract_sealed_from_public_key(public_key)
    sealed_private = extract_sealed_from_public_key(public_key)
    start_tick = 0  # 攻击者篡改为任意值
    end_tick = 999999999999
    
    # TPM 会验证 policy digest，发现不匹配（当前 clock 不在真实窗口内）
    with pytest.raises(TPM2Error, match="TPM_RC_POLICY_FAIL"):
        unseal_with_time_policy(
            esapi, srk_handle,
            sealed_public, sealed_private,
            start_tick, end_tick  # 即使传入任意值，TPM 会验证实际 clock
        )
```

### 6.6 真实 TPM vs swtpm

| 特性 | swtpm（模拟器） | 真实 TPM 2.0 |
|------|----------------|--------------|
| 用途 | 开发和测试 | 生产环境 |
| Policy 支持 | 完整支持 | 完整支持 |
| 时钟防篡改 | ❌ 可被软件修改 | ✅ 硬件维护 |
| 密钥绑定 | ❌ 无硬件绑定 | ✅ FIXEDTPM 绑定到芯片 |
| 物理安全 | ❌ 软件实现 | ✅ 防篡改封装 |
| 代码绕过防护 | ❌ 仅测试概念 | ✅ 真正不可绕过 |

**重要提示**：
- swtpm 仅用于开发环境测试 Policy 逻辑流程
- 生产环境必须使用真实 TPM 2.0 硬件
- 使用 swtpm 时，攻击者仍可修改 swtpm 状态文件绕过时间检查
- 只有真实 TPM 才能提供硬件层不可绕过的保护

### 6.7 部署检查清单

在启用 TPM Policy 前，确认以下条件：

- [ ] 服务器配备真实 TPM 2.0 硬件（非模拟器）
- [ ] TPM 固件版本无已知漏洞（检查 CVE）
- [ ] SRK（Storage Root Key）已创建且设置 FIXEDTPM
- [ ] TPM 所有权已正确配置
- [ ] 应用代码不记录/传输 unsealed seed
- [ ] 测试时间窗口内和窗口外的转换行为
- [ ] 测试 TPM 重启后的行为（reset_count 检测）
- [ ] 配置审计日志记录 Policy 相关事件
- [ ] 配置监控告警（异常的 Policy 失败次数）
- [ ] 文档化时间窗口映射策略（UTC 到 tick）
- [ ] 规划 TPM 时钟重置后的密钥更新流程

## 7. 常见问题与解决方案

### 7.1 TPM 设备访问权限

```bash
# 添加用户到 tss 组
sudo usermod -a -G tss $USER

# 设置 TPM 设备权限
sudo chmod 666 /dev/tpm0
sudo chmod 666 /dev/tpmrm0
```

### 7.2 TPM 模拟器未响应

```bash
# 检查模拟器进程
ps aux | grep swtpm

# 重启模拟器
pkill swtpm
swtpm socket --tpmstate dir=/tmp/tpm_state \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --tpm2 --flags not-need-init &
```

### 7.3 持久化句柄已存在

```bash
# 列出持久化句柄
tpm2_getcap handles-persistent

# 删除已存在的句柄
tpm2_evictcontrol -C o -c 0x81010001
```

## 8. 安全最佳实践

1. **核心密钥保护**
   - 设置 `TPMA_OBJECT_FIXEDTPM` 和 `TPMA_OBJECT_FIXEDPARENT`
   - 不要导出核心密钥

2. **访问控制**
   - 使用 TPM 的授权机制
   - 限制敏感操作的访问权限

3. **错误处理**
   - 不要在错误信息中泄露敏感信息
   - 实施速率限制防止暴力破解

4. **日志记录**
   - 记录所有 TPM 操作
   - 监控异常访问模式

## 9. 测试策略

### 9.1 单元测试

```python
import unittest

class TestTPMOperations(unittest.TestCase):
    def setUp(self):
        self.manager = TPMKeyManager()
    
    def test_core_key_generation(self):
        # 测试核心密钥生成
        pass
    
    def test_time_verification(self):
        # 测试时间验证
        pass
    
    def test_key_conversion(self):
        # 测试密钥转换
        pass
```

### 9.2 集成测试

- 测试完整的生成-转换流程
- 测试时间边界条件
- 测试错误密钥场景
- 测试 TPM 故障恢复

## 10. 参考资源

- [TPM 2.0 规范](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [tpm2-tools 文档](https://github.com/tpm2-software/tpm2-tools)
- [tpm2-pytss 文档](https://github.com/tpm2-software/tpm2-pytss)
- [Go TPM 库](https://github.com/google/go-tpm)
