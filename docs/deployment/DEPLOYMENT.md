# KCS 部署文档

## 1. 部署概述

本文档介绍如何将 KCS (Key Conversion System) 部署到生产环境。

### 1.1 部署架构选择

KCS 支持多种部署架构：

1. **单机部署**：所有组件部署在一台服务器上（适合小规模使用）
2. **分离部署**：前后端分离部署（推荐）
3. **容器化部署**：使用 Docker/Kubernetes（推荐用于生产环境）
4. **负载均衡部署**：多台服务器+负载均衡（高可用场景）

## 2. 硬件要求

### 2.1 生产环境最低要求

| 组件 | CPU | 内存 | 磁盘 | 特殊要求 |
|------|-----|------|------|----------|
| 后端服务 | 2 核 | 4GB | 20GB | **必须有 TPM 2.0** |
| 前端服务 | 1 核 | 2GB | 10GB | - |
| 数据库（可选） | 1 核 | 2GB | 20GB | - |

### 2.2 推荐配置

| 组件 | CPU | 内存 | 磁盘 | 备注 |
|------|-----|------|------|------|
| 后端服务 | 4 核 | 8GB | 50GB | SSD 推荐 |
| 前端服务 | 2 核 | 4GB | 20GB | - |
| 负载均衡 | 2 核 | 4GB | 20GB | Nginx/HAProxy |

### 2.3 TPM 要求

- **必须**：服务器配备 TPM 2.0 芯片
- **验证方法**：
  ```bash
  # Linux
  ls -l /dev/tpm*
  tpm2_getcap properties-fixed
  
  # Windows
  Get-Tpm
  ```

## 3. 软件要求

### 3.1 操作系统

**支持的操作系统**：
- Ubuntu 20.04 LTS / 22.04 LTS（推荐）
- CentOS 8+ / RHEL 8+
- Windows Server 2019/2022（支持但不推荐）

### 3.2 依赖软件

- Python 3.8+
- Node.js 16+ (仅用于构建前端)
- Nginx 1.18+
- TPM 2.0 TSS (tpm2-tools, libtss2)
- SSL 证书（Let's Encrypt 或商业证书）

## 4. 单机部署（快速开始）

### 4.1 安装系统依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3.8 \
    python3-pip \
    python3-venv \
    nginx \
    tpm2-tools \
    libtss2-dev \
    certbot \
    python3-certbot-nginx
```

### 4.2 部署后端

```bash
# 创建部署目录
sudo mkdir -p /opt/kcs
sudo chown $USER:$USER /opt/kcs

# 克隆代码
cd /opt/kcs
git clone https://github.com/qq940500529/KCS.git .

# 设置 Python 环境
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 创建生产配置
cp .env.example .env.production
nano .env.production
```

**生产环境配置示例** (`backend/.env.production`)：

```bash
# 服务器配置
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
SERVER_URL=https://kcs.yourdomain.com

# TPM 配置
TPM_ENABLED=true
TPM_SIMULATOR=false
TPM_DEVICE=/dev/tpm0

# 核心密钥配置
CORE_KEY_LABEL=kcs-core-key-v1
CORE_KEY_HANDLE=0x81010001

# 日志配置
LOG_LEVEL=INFO
LOG_FILE=/var/log/kcs/kcs.log

# 安全配置
SECRET_KEY=$(openssl rand -hex 32)
ALLOWED_ORIGINS=https://kcs.yourdomain.com

# 性能配置
WORKERS=4
MAX_REQUESTS=1000
TIMEOUT=30
```

### 4.3 初始化 TPM 核心密钥

```bash
# 检查 TPM 状态
tpm2_getcap properties-fixed

# 运行初始化脚本
cd /opt/kcs/backend
source venv/bin/activate
python -m src.init_core_key --url https://kcs.yourdomain.com
```

### 4.4 设置 Systemd 服务

创建 `/etc/systemd/system/kcs-backend.service`：

```ini
[Unit]
Description=KCS Backend Service
After=network.target

[Service]
Type=simple
User=kcs
Group=kcs
WorkingDirectory=/opt/kcs/backend
Environment="PATH=/opt/kcs/backend/venv/bin"
EnvironmentFile=/opt/kcs/backend/.env.production
ExecStart=/opt/kcs/backend/venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:5000 \
    --timeout 30 \
    --access-logfile /var/log/kcs/access.log \
    --error-logfile /var/log/kcs/error.log \
    src.main:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
# 创建用户
sudo useradd -r -s /bin/false kcs

# 创建日志目录
sudo mkdir -p /var/log/kcs
sudo chown kcs:kcs /var/log/kcs

# 设置权限
sudo chown -R kcs:kcs /opt/kcs

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable kcs-backend
sudo systemctl start kcs-backend

# 检查状态
sudo systemctl status kcs-backend
```

### 4.5 构建和部署前端

```bash
# 构建前端
cd /opt/kcs/frontend
npm install
npm run build

# 部署到 Nginx
sudo mkdir -p /var/www/kcs
sudo cp -r dist/* /var/www/kcs/
sudo chown -R www-data:www-data /var/www/kcs
```

### 4.6 配置 Nginx

创建 `/etc/nginx/sites-available/kcs`：

```nginx
# 强制 HTTPS
server {
    listen 80;
    server_name kcs.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name kcs.yourdomain.com;

    # SSL 配置
    ssl_certificate /etc/letsencrypt/live/kcs.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kcs.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # 安全头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # 前端静态文件
    root /var/www/kcs;
    index index.html;

    # 前端路由
    location / {
        try_files $uri $uri/ /index.html;
    }

    # 后端 API 代理
    location /api/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 超时设置
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # 健康检查
    location /health {
        proxy_pass http://127.0.0.1:5000/health;
        access_log off;
    }

    # 日志
    access_log /var/log/nginx/kcs-access.log;
    error_log /var/log/nginx/kcs-error.log;
}
```

启用站点：

```bash
# 启用配置
sudo ln -s /etc/nginx/sites-available/kcs /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启 Nginx
sudo systemctl restart nginx
```

### 4.7 配置 SSL 证书

```bash
# 使用 Let's Encrypt
sudo certbot --nginx -d kcs.yourdomain.com

# 自动续期
sudo certbot renew --dry-run
```

## 5. Docker 部署（推荐）

### 5.1 准备工作

确保服务器已安装：
- Docker 20.10+
- Docker Compose 2.0+

### 5.2 Docker Compose 配置

创建 `docker-compose.prod.yml`：

```yaml
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    ports:
      - "127.0.0.1:5000:5000"
    environment:
      - TPM_ENABLED=true
      - TPM_DEVICE=/dev/tpm0
      - SERVER_URL=https://kcs.yourdomain.com
    volumes:
      - ./backend/logs:/app/logs
      - /dev/tpm0:/dev/tpm0
      - /dev/tpmrm0:/dev/tpmrm0
    devices:
      - /dev/tpm0
      - /dev/tpmrm0
    restart: unless-stopped
    networks:
      - kcs-network

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./frontend/dist:/var/www/kcs:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - kcs-network

networks:
  kcs-network:
    driver: bridge
```

### 5.3 生产 Dockerfile

`backend/Dockerfile.prod`：

```dockerfile
FROM python:3.9-slim

# 安装 TPM 工具
RUN apt-get update && apt-get install -y \
    tpm2-tools \
    libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 复制应用
COPY . .

# 创建非 root 用户
RUN useradd -m -u 1000 kcs && \
    chown -R kcs:kcs /app

USER kcs

EXPOSE 5000

CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5000", \
     "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", \
     "src.main:app"]
```

### 5.4 部署

```bash
# 构建并启动
docker-compose -f docker-compose.prod.yml up -d

# 查看日志
docker-compose -f docker-compose.prod.yml logs -f

# 初始化核心密钥
docker-compose -f docker-compose.prod.yml exec backend \
    python -m src.init_core_key --url https://kcs.yourdomain.com
```

## 6. 高可用部署

### 6.1 架构设计

```
                    ┌──────────────┐
                    │ Load Balancer│
                    │   (Nginx)    │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
      ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
      │ Server 1│    │ Server 2│    │ Server 3│
      │  +TPM   │    │  +TPM   │    │  +TPM   │
      └─────────┘    └─────────┘    └─────────┘
```

**注意**：每台服务器都需要独立的 TPM，因此：
- 每台服务器都有独立的核心密钥
- 公钥需要指定特定服务器的 URL
- 负载均衡需要支持会话粘性（sticky session）

### 6.2 负载均衡配置

Nginx 负载均衡配置：

```nginx
upstream kcs_backend {
    # 使用 IP Hash 确保同一公钥总是路由到同一服务器
    ip_hash;
    
    server 192.168.1.10:5000 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:5000 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:5000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name kcs.yourdomain.com;

    # ... SSL 配置 ...

    location /api/ {
        proxy_pass http://kcs_backend;
        
        # 保持会话
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 7. 监控和日志

### 7.1 日志配置

```bash
# 配置日志轮转
sudo nano /etc/logrotate.d/kcs

/var/log/kcs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 kcs kcs
    sharedscripts
    postrotate
        systemctl reload kcs-backend > /dev/null 2>&1 || true
    endscript
}
```

### 7.2 监控指标

使用 Prometheus + Grafana 监控：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'kcs-backend'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
```

关键监控指标：
- 请求响应时间
- TPM 操作延迟
- 错误率
- 并发连接数
- 密钥生成/转换成功率

## 8. 备份和恢复

### 8.1 备份策略

**需要备份的内容**：
- ✅ 应用配置文件
- ✅ 日志文件（可选）
- ✅ SSL 证书
- ❌ TPM 核心密钥（**无法备份**，绑定到硬件）

**备份脚本**：

```bash
#!/bin/bash
# backup-kcs.sh

BACKUP_DIR="/backup/kcs"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR/$DATE

# 备份配置
cp /opt/kcs/backend/.env.production $BACKUP_DIR/$DATE/
cp /etc/nginx/sites-available/kcs $BACKUP_DIR/$DATE/
cp /etc/systemd/system/kcs-backend.service $BACKUP_DIR/$DATE/

# 备份 SSL 证书
cp -r /etc/letsencrypt $BACKUP_DIR/$DATE/

# 压缩
tar -czf $BACKUP_DIR/kcs-backup-$DATE.tar.gz -C $BACKUP_DIR/$DATE .
rm -rf $BACKUP_DIR/$DATE

# 保留最近 30 天的备份
find $BACKUP_DIR -name "kcs-backup-*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/kcs-backup-$DATE.tar.gz"
```

### 8.2 灾难恢复

**重要警告**：
- 如果服务器硬件损坏，TPM 核心密钥将**永久丢失**
- 所有使用该服务器生成的公钥将**无法解密**
- 这是设计特性，确保安全性

**恢复步骤**：
1. 在新服务器上安装系统和依赖
2. 恢复配置文件
3. 重新初始化 TPM 核心密钥（新密钥）
4. 重新部署应用

## 9. 安全加固

### 9.1 系统级安全

```bash
# 配置防火墙
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# 禁用不必要的服务
sudo systemctl disable <unused-service>

# 更新系统
sudo apt-get update && sudo apt-get upgrade -y
```

### 9.2 应用级安全

- 启用 HTTPS（强制）
- 配置 CORS 白名单
- 实施 API 速率限制
- 启用审计日志
- 定期更新依赖

### 9.3 TPM 安全

```bash
# 设置 TPM 访问权限
sudo chmod 600 /dev/tpm0
sudo chown kcs:kcs /dev/tpm0

# 检查 TPM 所有权
tpm2_getcap handles-all
```

## 10. 性能优化

### 10.1 后端优化

- 使用 Gunicorn 多进程
- 启用 HTTP/2
- 配置连接池
- 实施缓存策略

### 10.2 前端优化

- 启用 Gzip 压缩
- 配置浏览器缓存
- 使用 CDN（可选）
- 代码分割和懒加载

### 10.3 TPM 优化

- 复用 TPM 会话
- 缓存核心密钥句柄
- 限制并发 TPM 操作

## 11. 维护和更新

### 11.1 更新流程

```bash
# 1. 备份
./backup-kcs.sh

# 2. 拉取新代码
cd /opt/kcs
git pull

# 3. 更新依赖
cd backend
source venv/bin/activate
pip install -r requirements.txt

# 4. 重启服务
sudo systemctl restart kcs-backend

# 5. 验证
curl https://kcs.yourdomain.com/health
```

### 11.2 健康检查

```bash
# 检查后端服务
curl http://localhost:5000/health

# 检查 TPM 状态
tpm2_getcap properties-fixed

# 检查系统资源
htop
df -h
free -m
```

## 12. 故障排查

### 12.1 常见问题

| 问题 | 可能原因 | 解决方案 |
|------|----------|----------|
| 服务启动失败 | TPM 不可用 | 检查 TPM 设备和权限 |
| 密钥转换失败 | 核心密钥未初始化 | 运行初始化脚本 |
| 性能问题 | TPM 操作过慢 | 优化并发策略 |
| 证书过期 | SSL 证书未续期 | 运行 certbot renew |

### 12.2 日志分析

```bash
# 查看后端日志
sudo journalctl -u kcs-backend -f

# 查看 Nginx 日志
sudo tail -f /var/log/nginx/kcs-error.log

# 查看应用日志
sudo tail -f /var/log/kcs/kcs.log
```

## 13. 联系支持

如遇到部署问题，请：
1. 查看 [FAQ](../guides/FAQ.md)
2. 搜索 [GitHub Issues](https://github.com/qq940500529/KCS/issues)
3. 提交新的 Issue

---

**部署检查清单**：

- [ ] 服务器有 TPM 2.0 芯片
- [ ] 安装所有依赖
- [ ] 初始化核心密钥
- [ ] 配置生产环境变量
- [ ] 设置 Systemd 服务
- [ ] 配置 Nginx 反向代理
- [ ] 配置 SSL 证书
- [ ] 设置防火墙规则
- [ ] 配置日志轮转
- [ ] 设置监控和告警
- [ ] 配置备份任务
- [ ] 进行安全加固
- [ ] 性能测试
- [ ] 文档化部署信息
