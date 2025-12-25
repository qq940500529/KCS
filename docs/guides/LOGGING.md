# KCS 日志规范文档

## 1. 日志系统概述

KCS 系统使用 Python 标准库 `logging` 配合 `python-json-logger` 实现结构化日志记录。

**核心原则**：
- ✅ 记录所有操作和事件，便于审计和故障排查
- ❌ **严禁**记录任何敏感信息（私钥、转换密钥等）
- ✅ 使用 JSON 格式，便于日志分析和搜索

## 2. 日志分类

### 2.1 应用日志 (`/var/log/kcs/app.log`)

**用途**：记录系统运行状态和一般操作

**记录内容**：
- 系统启动/停止事件
- 配置加载信息
- 健康检查状态
- TPM 连接状态
- 性能指标

**示例**：
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "INFO",
  "logger": "kcs.main",
  "message": "KCS Backend started successfully",
  "tpm_available": true,
  "core_key_initialized": true
}
```

### 2.2 审计日志 (`/var/log/kcs/audit.log`)

**用途**：记录所有密钥相关操作，用于安全审计

**记录内容**：

#### ✅ 允许记录：
- 时间戳
- 操作类型（KEY_GENERATION, KEY_CONVERSION）
- 客户端 IP 地址
- 请求参数（密钥长度、转换密钥数量、时间窗口）
- 操作结果（成功/失败）
- 失败原因（时间不匹配、URL 不匹配、转换密钥错误等）
- **公钥哈希值**（SHA256，不是公钥本身）
- TPM 操作耗时
- 请求 ID（用于关联多个日志）

#### ❌ 严禁记录：
- **私钥**（Private Key）
- **转换密钥**（Transfer Key）
- **公钥完整内容**（仅记录哈希）
- 核心密钥句柄详细信息
- TPM 内部密钥材料
- 任何可用于恢复私钥的中间值

**示例**：
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "INFO",
  "logger": "kcs.audit",
  "action": "KEY_GENERATION",
  "request_id": "req-abc123",
  "client_ip": "192.168.1.100",
  "request_params": {
    "key_length": 12,
    "transfer_keys_count": 1,
    "time_window_start": "2024-01-01T00:00:00Z",
    "time_window_end": "2024-12-31T23:59:59Z"
  },
  "result": "success",
  "public_key_hash": "sha256:a1b2c3d4...",
  "duration_ms": 245
}
```

### 2.3 安全日志 (`/var/log/kcs/security.log`)

**用途**：记录安全相关事件和可疑活动

**记录内容**：
- 失败的转换尝试（可能的暴力破解）
- 异常的请求模式
- 速率限制触发
- IP 封禁事件
- 时间验证失败
- URL 验证失败

**示例**：
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "WARNING",
  "logger": "kcs.security",
  "event": "BRUTE_FORCE_DETECTED",
  "client_ip": "192.168.1.200",
  "failed_attempts": 15,
  "time_window_seconds": 3600,
  "action_taken": "IP_BLOCKED",
  "block_duration_seconds": 3600
}
```

### 2.4 错误日志 (`/var/log/kcs/error.log`)

**用途**：记录系统错误和异常

**记录内容**：
- Python 异常堆栈
- TPM 操作失败
- 数据库连接错误
- 配置加载失败
- 未预期的系统状态

**示例**：
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "ERROR",
  "logger": "kcs.tpm",
  "message": "TPM operation failed",
  "error_type": "TPM2Error",
  "error_message": "TPM device not responding",
  "stack_trace": "...",
  "request_id": "req-abc123"
}
```

## 3. 敏感信息过滤机制

### 3.1 自动过滤函数

```python
import hashlib
from typing import Any, Dict

# 定义所有敏感字段名称
SENSITIVE_FIELDS = {
    'private_key',
    'transfer_key',
    'transfer_keys',
    'public_key',  # 将被替换为哈希
    'core_key_material',
    'tpm_key_handle',
    'encryption_key',
    'master_key',
    'secret_key',
    'password'
}

def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    清理日志数据，移除所有敏感信息
    
    Args:
        data: 原始数据字典
        
    Returns:
        清理后的数据字典
    """
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    
    for key, value in data.items():
        # 检查是否为敏感字段
        if key in SENSITIVE_FIELDS:
            # 对于公钥，记录哈希值
            if key == 'public_key' and isinstance(value, str):
                sanitized['public_key_hash'] = hashlib.sha256(
                    value.encode()
                ).hexdigest()
            else:
                # 其他敏感字段标记为已编辑
                sanitized[key] = '***REDACTED***'
        # 递归处理嵌套字典
        elif isinstance(value, dict):
            sanitized[key] = sanitize_log_data(value)
        # 递归处理列表
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_log_data(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            sanitized[key] = value
    
    return sanitized
```

### 3.2 日志装饰器

```python
import functools
from typing import Callable

def log_api_call(logger):
    """
    装饰器：自动记录 API 调用，同时过滤敏感信息
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 记录请求（已过滤）
            safe_kwargs = sanitize_log_data(kwargs)
            logger.info(f"API call: {func.__name__}", extra={
                "function": func.__name__,
                "args": safe_kwargs
            })
            
            try:
                # 执行函数
                result = await func(*args, **kwargs)
                
                # 记录成功（已过滤）
                safe_result = sanitize_log_data(result)
                logger.info(f"API success: {func.__name__}", extra={
                    "function": func.__name__,
                    "result": safe_result
                })
                
                return result
            except Exception as e:
                # 记录错误
                logger.error(f"API error: {func.__name__}", extra={
                    "function": func.__name__,
                    "error": str(e)
                }, exc_info=True)
                raise
        
        return wrapper
    return decorator

# 使用示例
@log_api_call(audit_logger)
async def generate_keys(request: KeyGenerationRequest):
    # 实现密钥生成
    pass
```

## 4. 日志配置

### 4.1 日志配置文件 (`logging.conf`)

```ini
[loggers]
keys=root,kcs,audit,security

[handlers]
keys=consoleHandler,appFileHandler,auditFileHandler,securityFileHandler,errorFileHandler

[formatters]
keys=jsonFormatter

[logger_root]
level=INFO
handlers=consoleHandler,errorFileHandler

[logger_kcs]
level=INFO
handlers=appFileHandler
qualname=kcs
propagate=0

[logger_audit]
level=INFO
handlers=auditFileHandler
qualname=kcs.audit
propagate=0

[logger_security]
level=WARNING
handlers=securityFileHandler
qualname=kcs.security
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=DEBUG
formatter=jsonFormatter
args=(sys.stdout,)

[handler_appFileHandler]
class=handlers.RotatingFileHandler
level=INFO
formatter=jsonFormatter
args=('/var/log/kcs/app.log', 'a', 10485760, 10)

[handler_auditFileHandler]
class=handlers.RotatingFileHandler
level=INFO
formatter=jsonFormatter
args=('/var/log/kcs/audit.log', 'a', 10485760, 30)

[handler_securityFileHandler]
class=handlers.RotatingFileHandler
level=WARNING
formatter=jsonFormatter
args=('/var/log/kcs/security.log', 'a', 10485760, 30)

[handler_errorFileHandler]
class=handlers.RotatingFileHandler
level=ERROR
formatter=jsonFormatter
args=('/var/log/kcs/error.log', 'a', 10485760, 10)

[formatter_jsonFormatter]
class=pythonjsonlogger.jsonlogger.JsonFormatter
format=%(asctime)s %(name)s %(levelname)s %(message)s
```

### 4.2 日志初始化代码

```python
import logging
import logging.config
from pathlib import Path

def setup_logging():
    """
    初始化日志系统
    """
    # 确保日志目录存在
    log_dir = Path("/var/log/kcs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 设置日志文件权限
    for log_file in log_dir.glob("*.log"):
        log_file.chmod(0o600)  # 仅所有者可读写
    
    # 加载日志配置
    logging.config.fileConfig('logging.conf')
    
    # 获取日志记录器
    app_logger = logging.getLogger('kcs')
    audit_logger = logging.getLogger('kcs.audit')
    security_logger = logging.getLogger('kcs.security')
    
    return app_logger, audit_logger, security_logger
```

## 5. 日志轮转和归档

### 5.1 日志轮转策略

- **应用日志**: 每个文件最大 10MB，保留 10 个文件（约 100MB）
- **审计日志**: 每个文件最大 10MB，保留 30 个文件（约 300MB，保留 30 天）
- **安全日志**: 每个文件最大 10MB，保留 30 个文件（约 300MB）
- **错误日志**: 每个文件最大 10MB，保留 10 个文件（约 100MB）

### 5.2 日志归档

```bash
# /etc/logrotate.d/kcs
/var/log/kcs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0600 kcs kcs
    sharedscripts
    postrotate
        systemctl reload kcs-backend > /dev/null 2>&1 || true
    endscript
}
```

## 6. 日志监控和告警

### 6.1 关键监控指标

- 错误日志数量（ERROR、CRITICAL 级别）
- 失败的密钥转换尝试（可能的暴力破解）
- TPM 操作失败率
- API 响应时间
- 异常的 IP 访问模式

### 6.2 告警规则示例

```python
from datetime import datetime, timedelta

def check_brute_force_attacks():
    """
    检查是否存在暴力破解攻击
    """
    # 获取最近1小时的失败尝试
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    
    # 从安全日志中统计
    failed_attempts = count_failed_conversions(since=one_hour_ago)
    
    # 按 IP 分组
    attempts_by_ip = group_by_ip(failed_attempts)
    
    # 检查是否有 IP 超过阈值
    for ip, count in attempts_by_ip.items():
        if count > 10:
            # 触发告警
            send_alert(
                level="HIGH",
                message=f"Possible brute force attack from {ip}",
                details=f"{count} failed attempts in last hour"
            )
            
            # 封禁 IP
            block_ip(ip, duration=3600)
```

## 7. 合规性

### 7.1 数据保护法规

日志记录遵守以下法规要求：
- 不记录个人敏感信息（私钥、密码等）
- 仅记录必要的审计信息
- 日志访问权限严格控制
- 日志保留期限符合法规要求（30天）

### 7.2 安全标准

- ISO 27001：信息安全管理
- SOC 2：审计日志要求
- GDPR：数据最小化原则

## 8. 最佳实践

1. **永远不要记录敏感信息** - 使用 `sanitize_log_data` 函数过滤
2. **使用结构化日志** - JSON 格式便于分析
3. **添加请求 ID** - 便于跟踪单个请求的完整生命周期
4. **合理设置日志级别** - 避免日志过多或过少
5. **定期审查日志** - 发现潜在的安全问题
6. **保护日志文件** - 设置正确的文件权限（600）
7. **监控日志大小** - 避免磁盘空间耗尽
8. **测试日志过滤** - 确保敏感信息不会被记录

## 9. 常见问题

### Q: 为什么不记录完整的公钥？

A: 公钥虽然不是私钥，但包含加密后的私钥信息。记录哈希值足以关联操作，同时避免日志泄露导致的潜在风险。

### Q: 日志文件权限应该设置为多少？

A: 应设置为 600（仅所有者可读写），避免未授权访问。

### Q: 如何验证日志中没有敏感信息？

A: 定期审查日志文件，搜索关键字如 "private_key", "transfer_key" 等，确保它们都被标记为 "***REDACTED***"。

### Q: 日志保留多久？

A: 审计日志建议保留至少 30 天，符合大多数合规要求。生产环境可根据需求延长。

---

**重要提醒**：日志记录是安全审计的重要组成部分，但必须确保不会记录任何敏感信息。始终使用 `sanitize_log_data` 函数过滤数据，切勿直接记录原始请求或响应。
