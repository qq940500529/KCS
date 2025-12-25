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

TPM Policy 可以实现基于条件的密钥使用控制。

### 4.1 时间策略示例

```python
def create_time_bound_key(esapi, start_time, end_time):
    """
    创建时间绑定的密钥
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
        # 1. 获取 TPM 时间种子
        tpm_time = self.get_tpm_time()
        
        # 2. 从 TPM 获取核心密钥材料
        core_key_material = self._get_core_key_material()
        
        # 3. 使用所有转换密钥派生主密钥（自动排序，顺序无关）
        master_key = self._derive_master_key_multi(
            core_key_material,
            transfer_keys,
            tpm_time["clock"]
        )
        
        # 4. 加密私钥
        from cryptography.fernet import Fernet
        import base64
        
        # 使用派生的主密钥创建 Fernet 实例
        fernet_key = base64.urlsafe_b64encode(master_key)
        f = Fernet(fernet_key)
        encrypted_private_key = f.encrypt(private_key.encode())
        
        # 5. 计算每个转换密钥的哈希
        import hashlib
        transfer_keys_hashes = [
            hashlib.sha256(key.encode()).hexdigest()
            for key in transfer_keys
        ]
        
        # 6. 生成公钥（封装所有信息）
        public_key_data = {
            "version": 1,
            "encrypted_private_key": base64.b64encode(
                encrypted_private_key
            ).decode(),
            "server_url": server_url,
            "time_window": time_window,
            "tpm_time_seed": tpm_time["clock"],
            "transfer_keys_count": len(transfer_keys),
            "transfer_keys_hashes": transfer_keys_hashes
        }
        
        public_key = "PUB_" + base64.b64encode(
            json.dumps(public_key_data).encode()
        ).decode()
        
        return public_key
    
    def convert_key(self, public_key, transfer_keys):
        """
        转换公钥为私钥（支持任意数量转换密钥验证，输入顺序无关）
        
        Args:
            public_key: 公钥字符串
            transfer_keys: 用户提供的转换密钥列表（顺序可任意）
        
        Returns:
            解密的私钥字符串
        
        Raises:
            ValueError: 转换密钥验证失败
        """
        import json
        import base64
        import hashlib
        
        # 1. 解析公钥
        public_key_data = json.loads(
            base64.b64decode(public_key[4:])
        )
        
        # 2. 验证转换密钥数量
        required_count = public_key_data["transfer_keys_count"]
        provided_count = len(transfer_keys)
        
        if provided_count != required_count:
            raise ValueError(
                f"需要 {required_count} 个转换密钥，但只提供了 {provided_count} 个"
            )
        
        # 3. 验证每个转换密钥的哈希（顺序无关，使用集合比较）
        stored_hashes = set(public_key_data["transfer_keys_hashes"])
        provided_hashes = set(
            hashlib.sha256(key.encode()).hexdigest()
            for key in transfer_keys
        )
        
        if provided_hashes != stored_hashes:
            raise ValueError(
                "一个或多个转换密钥不正确，所有转换密钥必须完全正确"
            )
        
        # 4. 验证时间
        current_time = self.get_tpm_time()
        # ... 时间验证逻辑
        
        # 5. 重新派生主密钥（使用所有转换密钥，自动排序）
        core_key_material = self._get_core_key_material()
        master_key = self._derive_master_key_multi(
            core_key_material,
            transfer_keys,
            public_key_data["tpm_time_seed"]
        )
        
        # 6. 解密私钥
        from cryptography.fernet import Fernet
        fernet_key = base64.urlsafe_b64encode(master_key)
        f = Fernet(fernet_key)
        
        encrypted_private_key = base64.b64decode(
            public_key_data["encrypted_private_key"]
        )
        private_key = f.decrypt(encrypted_private_key).decode()
        
        return private_key
    
    def _derive_master_key_multi(self, core_key_material, transfer_keys, tpm_time_seed):
        """
        使用多个转换密钥派生主密钥
        支持任意数量的转换密钥，输入顺序无关
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        import hashlib
        
        # 对转换密钥排序（确保顺序无关）
        sorted_keys = sorted(transfer_keys)
        combined_keys = '|'.join(sorted_keys).encode()
        keys_hash = hashlib.sha256(combined_keys).digest()
        
        info = f"KCS-v1-{tpm_time_seed}-{len(transfer_keys)}".encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=keys_hash,
            info=info
        )
        
        return hkdf.derive(core_key_material)
    
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

## 6. 常见问题与解决方案

### 6.1 TPM 设备访问权限

```bash
# 添加用户到 tss 组
sudo usermod -a -G tss $USER

# 设置 TPM 设备权限
sudo chmod 666 /dev/tpm0
sudo chmod 666 /dev/tpmrm0
```

### 6.2 TPM 模拟器未响应

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

### 6.3 持久化句柄已存在

```bash
# 列出持久化句柄
tpm2_getcap handles-persistent

# 删除已存在的句柄
tpm2_evictcontrol -C o -c 0x81010001
```

## 7. 安全最佳实践

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

## 8. 测试策略

### 8.1 单元测试

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

### 8.2 集成测试

- 测试完整的生成-转换流程
- 测试时间边界条件
- 测试错误密钥场景
- 测试 TPM 故障恢复

## 9. 参考资源

- [TPM 2.0 规范](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [tpm2-tools 文档](https://github.com/tpm2-software/tpm2-tools)
- [tpm2-pytss 文档](https://github.com/tpm2-software/tpm2-pytss)
- [Go TPM 库](https://github.com/google/go-tpm)
