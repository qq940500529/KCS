# 贡献指南

欢迎为 KCS (Key Conversion System) 项目做出贡献！本文档将帮助您了解如何参与项目开发。

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发流程](#开发流程)
- [代码规范](#代码规范)
- [提交规范](#提交规范)
- [测试要求](#测试要求)
- [文档贡献](#文档贡献)
- [问题报告](#问题报告)
- [功能请求](#功能请求)

## 行为准则

### 我们的承诺

为了营造一个开放和友好的环境，我们承诺让参与项目和社区的每个人都获得无骚扰的体验，无论年龄、体型、残疾、种族、性别特征、性别认同和表达、经验水平、教育程度、社会经济地位、国籍、外貌、种族、宗教或性取向如何。

### 我们的标准

**积极行为示例**：
- 使用友好和包容的语言
- 尊重不同的观点和经验
- 优雅地接受建设性批评
- 关注什么对社区最有利
- 对其他社区成员表示同情

**不可接受的行为示例**：
- 使用性化语言或图像
- 挑衅、侮辱性或贬损性评论，以及人身攻击
- 公开或私下骚扰
- 未经明确许可，发布他人的私人信息
- 在专业环境中可能被视为不适当的其他行为

## 如何贡献

### 贡献方式

您可以通过以下方式为项目做出贡献：

1. **报告 Bug**：发现问题？请提交详细的 Issue
2. **建议新功能**：有好想法？我们很乐意听取
3. **改进文档**：文档永远可以更好
4. **编写代码**：修复 Bug 或实现新功能
5. **代码审查**：帮助审查其他人的 Pull Request
6. **回答问题**：在 Issues 和 Discussions 中帮助他人

### 第一次贡献？

如果您是第一次为开源项目做贡献，可以从以下开始：

- 查找标记为 `good first issue` 的问题
- 查找标记为 `help wanted` 的问题
- 改进文档
- 修复拼写错误

## 开发流程

### 1. Fork 并克隆仓库

```bash
# Fork 仓库到您的 GitHub 账号
# 然后克隆您的 Fork

git clone https://github.com/YOUR_USERNAME/KCS.git
cd KCS

# 添加上游仓库
git remote add upstream https://github.com/qq940500529/KCS.git
```

### 2. 创建分支

```bash
# 确保主分支是最新的
git checkout main
git pull upstream main

# 创建新分支
git checkout -b feature/your-feature-name
# 或
git checkout -b fix/your-bug-fix
```

分支命名规范：
- `feature/xxx`：新功能
- `fix/xxx`：Bug 修复
- `docs/xxx`：文档改进
- `refactor/xxx`：代码重构
- `test/xxx`：测试相关

### 3. 设置开发环境

参考 [开发环境搭建指南](docs/guides/DEVELOPMENT_SETUP.md) 设置您的开发环境。

### 4. 进行更改

- 编写代码
- 遵循代码规范（见下文）
- 编写或更新测试
- 更新相关文档

### 5. 提交更改

```bash
# 添加更改
git add .

# 提交（遵循提交规范）
git commit -m "feat: add new key generation algorithm"

# 推送到您的 Fork
git push origin feature/your-feature-name
```

### 6. 创建 Pull Request

1. 访问您的 Fork 在 GitHub 上的页面
2. 点击 "New Pull Request"
3. 选择您的分支
4. 填写 PR 模板
5. 提交 Pull Request

### 7. 代码审查

- 维护者会审查您的代码
- 根据反馈进行修改
- 修改后推送到同一分支（PR 会自动更新）

### 8. 合并

- PR 被批准后，维护者会合并您的代码
- 您的贡献将出现在下一个版本中！

## 代码规范

### Python 代码规范

遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格指南。

**关键点**：
- 使用 4 个空格缩进
- 行长度不超过 120 字符
- 函数和变量使用 `snake_case`
- 类使用 `PascalCase`
- 常量使用 `UPPER_CASE`

**示例**：

```python
"""模块文档字符串"""

import os
import sys

from typing import Dict, List, Optional


class KeyManager:
    """类文档字符串"""
    
    DEFAULT_KEY_LENGTH = 12  # 常量
    
    def __init__(self, config: Dict[str, any]):
        """初始化方法"""
        self.config = config
        self._private_keys = []  # 私有属性使用下划线前缀
    
    def generate_key(self, length: int = 12) -> str:
        """
        生成密钥
        
        Args:
            length: 密钥长度，默认 12
            
        Returns:
            生成的密钥字符串
            
        Raises:
            ValueError: 如果长度无效
        """
        if not 6 <= length <= 16:
            raise ValueError("Length must be between 6 and 16")
        
        # 实现...
        return generated_key
```

**使用工具**：

```bash
# 格式化代码
black backend/src/

# 检查代码风格
flake8 backend/src/

# 类型检查
mypy backend/src/
```

### JavaScript/TypeScript 代码规范

遵循 [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)。

**关键点**：
- 使用 2 个空格缩进
- 使用分号
- 使用单引号（除非需要转义）
- 使用 `camelCase` 命名变量和函数
- 使用 `PascalCase` 命名类和组件

**示例**：

```typescript
import React, { useState } from 'react';

interface KeyGenerationProps {
  onGenerate: (key: string) => void;
  maxLength?: number;
}

export const KeyGeneration: React.FC<KeyGenerationProps> = ({
  onGenerate,
  maxLength = 16,
}) => {
  const [keyLength, setKeyLength] = useState<number>(12);
  
  const handleGenerate = (): void => {
    // 实现...
    onGenerate(generatedKey);
  };
  
  return (
    <div className="key-generation">
      {/* JSX */}
    </div>
  );
};
```

**使用工具**：

```bash
# 格式化代码
npm run format

# 检查代码
npm run lint

# 类型检查
npm run type-check
```

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范。

### 提交消息格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type（类型）

- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更改
- `style`: 代码格式（不影响代码运行的变动）
- `refactor`: 重构（既不是新增功能，也不是修复 Bug）
- `perf`: 性能优化
- `test`: 添加或修改测试
- `chore`: 构建过程或辅助工具的变动
- `ci`: CI 配置和脚本的变动
- `revert`: 回滚之前的提交

### Scope（范围）

可选，表示影响的范围：
- `backend`: 后端代码
- `frontend`: 前端代码
- `tpm`: TPM 相关
- `crypto`: 加密算法
- `api`: API 接口
- `docs`: 文档
- `deps`: 依赖项

### 示例

```bash
# 新功能
git commit -m "feat(crypto): add AES-256-GCM encryption"

# Bug 修复
git commit -m "fix(backend): correct time window validation logic"

# 文档
git commit -m "docs: update API documentation for key conversion"

# 重构
git commit -m "refactor(tpm): improve core key generation algorithm"

# 性能优化
git commit -m "perf(backend): optimize TPM operation caching"

# 多行提交
git commit -m "feat(frontend): add key generation UI

- Add form for key configuration
- Add result display component
- Implement client-side validation

Closes #123"
```

## 测试要求

### 编写测试

所有新功能和 Bug 修复都应该有相应的测试。

**后端测试**（Python）：

```python
import unittest
from src.crypto.key_generator import generate_private_key


class TestKeyGeneration(unittest.TestCase):
    """测试密钥生成"""
    
    def test_generate_private_key_default_length(self):
        """测试默认长度密钥生成"""
        key = generate_private_key()
        self.assertEqual(len(key), 12)
    
    def test_generate_private_key_custom_length(self):
        """测试自定义长度密钥生成"""
        key = generate_private_key(length=16)
        self.assertEqual(len(key), 16)
    
    def test_generate_private_key_contains_all_character_types(self):
        """测试生成的密钥包含所有字符类型"""
        key = generate_private_key()
        
        has_upper = any(c.isupper() for c in key)
        has_lower = any(c.islower() for c in key)
        has_digit = any(c.isdigit() for c in key)
        has_symbol = any(not c.isalnum() for c in key)
        
        self.assertTrue(has_upper)
        self.assertTrue(has_lower)
        self.assertTrue(has_digit)
        self.assertTrue(has_symbol)
    
    def test_generate_private_key_invalid_length(self):
        """测试无效长度抛出异常"""
        with self.assertRaises(ValueError):
            generate_private_key(length=5)
        
        with self.assertRaises(ValueError):
            generate_private_key(length=17)


if __name__ == '__main__':
    unittest.main()
```

**前端测试**（JavaScript/React）：

```typescript
import { render, screen, fireEvent } from '@testing-library/react';
import { KeyGeneration } from './KeyGeneration';

describe('KeyGeneration', () => {
  it('renders key generation form', () => {
    render(<KeyGeneration onGenerate={jest.fn()} />);
    
    expect(screen.getByText('Generate Key')).toBeInTheDocument();
  });
  
  it('calls onGenerate when button is clicked', () => {
    const handleGenerate = jest.fn();
    render(<KeyGeneration onGenerate={handleGenerate} />);
    
    const button = screen.getByText('Generate');
    fireEvent.click(button);
    
    expect(handleGenerate).toHaveBeenCalled();
  });
  
  it('validates key length input', () => {
    render(<KeyGeneration onGenerate={jest.fn()} />);
    
    const input = screen.getByLabelText('Key Length');
    fireEvent.change(input, { target: { value: '20' } });
    
    expect(screen.getByText('Length must be between 6 and 16')).toBeInTheDocument();
  });
});
```

### 运行测试

```bash
# 后端测试
cd backend
pytest tests/

# 前端测试
cd frontend
npm test

# 测试覆盖率
cd backend
pytest --cov=src tests/

cd frontend
npm test -- --coverage
```

### 测试覆盖率要求

- 新功能应达到至少 80% 的测试覆盖率
- 关键安全功能应达到 90%+ 的覆盖率

## 文档贡献

### 文档类型

- **用户文档**：如何使用 KCS
- **开发文档**：如何开发和扩展 KCS
- **API 文档**：API 接口说明
- **架构文档**：系统设计和架构

### 文档风格

- 使用清晰、简洁的语言
- 提供代码示例
- 包含截图和图表（如适用）
- 保持更新

### 文档位置

- 用户文档：`docs/guides/`
- API 文档：`docs/api/`
- 架构文档：`docs/architecture/`
- 部署文档：`docs/deployment/`

## 问题报告

### 报告 Bug

提交 Bug 报告时，请包含：

1. **简短描述**：问题的简要说明
2. **重现步骤**：详细的重现步骤
3. **预期行为**：您期望发生什么
4. **实际行为**：实际发生了什么
5. **环境信息**：
   - 操作系统和版本
   - Python/Node.js 版本
   - KCS 版本
   - TPM 版本（如相关）
6. **日志和截图**：相关的错误日志或截图

### Bug 报告模板

```markdown
**描述 Bug**
简要描述问题

**重现步骤**
1. 前往 '...'
2. 点击 '....'
3. 滚动到 '....'
4. 看到错误

**预期行为**
描述您期望发生什么

**截图**
如果适用，添加截图以帮助解释问题

**环境信息**
- OS: [例如 Ubuntu 22.04]
- Python 版本: [例如 3.9.7]
- KCS 版本: [例如 1.0.0]
- TPM 版本: [例如 2.0]

**附加信息**
任何其他相关信息
```

## 功能请求

### 提交功能请求

提交功能请求时，请包含：

1. **问题描述**：这个功能解决什么问题？
2. **建议解决方案**：您建议如何实现？
3. **替代方案**：考虑过其他方案吗？
4. **附加上下文**：任何其他相关信息

### 功能请求模板

```markdown
**您的功能请求是否与某个问题相关？**
清晰简洁地描述问题，例如"我总是因为 [...] 而感到沮丧"

**描述您想要的解决方案**
清晰简洁地描述您想要发生什么

**描述您考虑过的替代方案**
清晰简洁地描述您考虑过的任何替代解决方案或功能

**附加上下文**
在此添加关于功能请求的任何其他上下文或截图
```

## Pull Request 审查

### 作为提交者

- 及时响应审查意见
- 保持 PR 小而集中
- 更新文档和测试
- 确保 CI 通过

### 作为审查者

- 保持建设性和礼貌
- 关注代码质量、安全性、性能
- 检查测试覆盖率
- 验证文档是否更新

## 社区

### 交流渠道

- **GitHub Issues**：Bug 报告和功能请求
- **GitHub Discussions**：一般讨论和问答
- **Email**：qq940500529@example.com（项目维护者）

### 获得帮助

如果您需要帮助：
1. 查看文档
2. 搜索现有的 Issues
3. 在 Discussions 中提问
4. 联系维护者

## 许可证

通过贡献，您同意您的贡献将根据项目的许可证进行许可。

## 感谢

感谢您为 KCS 项目做出贡献！您的帮助使这个项目变得更好。

---

**有问题？** 随时联系维护者或在 Discussions 中提问！
