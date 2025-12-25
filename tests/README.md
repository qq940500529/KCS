# KCS 测试

本目录包含 KCS 项目的测试套件。

## 测试类型

### 单元测试 (`unit/`)

测试单个函数或类的功能，不依赖外部系统。

**后端单元测试示例**：
```python
# tests/unit/test_key_generator.py
import unittest
from backend.src.crypto.key_generator import generate_private_key

class TestKeyGenerator(unittest.TestCase):
    def test_generate_private_key_length(self):
        key = generate_private_key(length=12)
        self.assertEqual(len(key), 12)
```

**前端单元测试示例**：
```typescript
// tests/unit/KeyGeneration.test.tsx
import { render, screen } from '@testing-library/react';
import { KeyGeneration } from '@/components/KeyGeneration';

test('renders key generation button', () => {
  render(<KeyGeneration />);
  expect(screen.getByText('Generate Key')).toBeInTheDocument();
});
```

### 集成测试 (`integration/`)

测试多个模块之间的交互，可能涉及数据库、TPM 模拟器等。

**示例**：
```python
# tests/integration/test_key_flow.py
def test_complete_key_generation_flow():
    import json
    
    # 生成密钥
    result = api_client.post('/api/v1/keys/generate', json={...})
    
    # 转换密钥
    convert_result = api_client.post('/api/v1/keys/convert', json={
        'public_key': result['public_key'],
        'transfer_keys': result['transfer_keys']
    })
    
    # 私钥现在是 JSON 格式，需要解析
    original_key_data = json.loads(result['private_key'])
    converted_key_data = json.loads(convert_result['private_key'])
    
    # 验证密钥字符串一致
    assert converted_key_data['key'] == original_key_data['key']
    # 验证时间窗口一致
    assert converted_key_data['time_window'] == original_key_data['time_window']
```

### 端到端测试 (`e2e/`)

测试完整的用户流程，从前端到后端。

**示例**（使用 Playwright）：
```typescript
// tests/e2e/key-generation.spec.ts
test('complete key generation and conversion flow', async ({ page }) => {
  await page.goto('http://localhost:3000');
  
  // 生成密钥
  await page.click('text=Generate Keys');
  await page.fill('[name="keyLength"]', '12');
  await page.click('button:has-text("Generate")');
  
  // 验证结果显示
  await expect(page.locator('.private-key')).toBeVisible();
  await expect(page.locator('.public-key')).toBeVisible();
  
  // 复制公钥和转换密钥
  const publicKey = await page.locator('.public-key').textContent();
  const transferKey = await page.locator('.transfer-key').textContent();
  
  // 转换密钥
  await page.click('text=Convert Key');
  await page.fill('[name="publicKey"]', publicKey);
  await page.fill('[name="transferKey"]', transferKey);
  await page.click('button:has-text("Convert")');
  
  // 验证私钥恢复
  await expect(page.locator('.converted-key')).toBeVisible();
});
```

## 运行测试

### 后端测试

```bash
cd backend

# 运行所有测试
pytest

# 运行特定测试文件
pytest tests/unit/test_key_generator.py

# 运行带覆盖率的测试
pytest --cov=src --cov-report=html

# 运行标记的测试
pytest -m "not slow"
```

### 前端测试

```bash
cd frontend

# 运行所有测试
npm test

# 运行测试（监视模式）
npm test -- --watch

# 运行覆盖率测试
npm test -- --coverage

# 运行特定测试文件
npm test KeyGeneration.test.tsx
```

### 集成测试

```bash
# 确保后端和 TPM 模拟器正在运行
cd tests/integration
pytest
```

### 端到端测试

```bash
# 确保前后端都在运行
cd tests/e2e
npx playwright test

# 运行特定测试
npx playwright test key-generation.spec.ts

# 调试模式
npx playwright test --debug
```

## 测试覆盖率目标

- **单元测试**：80%+ 代码覆盖率
- **集成测试**：覆盖所有主要 API 端点
- **端到端测试**：覆盖所有用户流程

## 测试最佳实践

1. **隔离性**：每个测试应该独立运行
2. **可重复性**：测试结果应该一致
3. **清晰性**：测试名称应该描述测试内容
4. **速度**：单元测试应该快速执行
5. **维护性**：测试代码应该易于维护

## Mock 和 Fixture

### TPM Mock

```python
# tests/fixtures/tpm_mock.py
class MockTPM:
    def __init__(self):
        self.clock = 1000000
        self.reset_count = 0
    
    def read_clock(self):
        return {
            'clock': self.clock,
            'reset_count': self.reset_count
        }
    
    def hmac(self, handle, data, alg):
        # 模拟 HMAC 操作
        return {'buffer': b'mocked_hmac_result'}
```

### API Mock

```typescript
// tests/mocks/api.ts
export const mockApi = {
  generateKeys: jest.fn().mockResolvedValue({
    success: true,
    data: {
      private_key: '{"key":"test_key_123","time_window":{"start":"2024-01-01T00:00:00Z","end":"2024-12-31T23:59:59Z"}}',
      transfer_keys: ['TK-test'],
      public_key: 'PUB_test'
    }
  })
};
```

## 持续集成

测试在 CI/CD 流程中自动运行：

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
      - name: Run tests
        run: |
          cd backend
          pytest --cov=src
```

## 贡献测试

为新功能添加测试时：

1. 编写测试用例
2. 确保测试通过
3. 检查代码覆盖率
4. 更新测试文档

查看 [CONTRIBUTING.md](../CONTRIBUTING.md) 了解更多信息。
