# Frontend Source Code

本目录包含 KCS 前端应用的源代码。

## 目录结构

```
src/
├── components/   # React 组件
├── pages/        # 页面组件
├── services/     # API 服务层
├── utils/        # 工具函数
├── App.tsx       # 应用根组件
└── main.tsx      # 应用入口
```

## 主要组件

### Pages (`pages/`)
- `KeyGenerationPage.tsx`: 密钥生成页面
- `KeyConversionPage.tsx`: 密钥转换页面
- `HomePage.tsx`: 首页

### Components (`components/`)
- `ConfigurationForm.tsx`: 配置表单
- `ResultDisplay.tsx`: 结果展示
- `TimeWindowSelector.tsx`: 时间窗口选择器
- `KeyValidator.tsx`: 密钥验证器
- `Header.tsx`: 页头组件
- `Footer.tsx`: 页脚组件

### Services (`services/`)
- `api.ts`: API 客户端
- `keyService.ts`: 密钥相关服务
- `timeService.ts`: 时间相关服务

### Utils (`utils/`)
- `validation.ts`: 验证函数
- `formatting.ts`: 格式化函数
- `constants.ts`: 常量定义

## 技术栈

- React 18+
- TypeScript
- Vite（构建工具）
- React Router（路由）
- Axios（HTTP 客户端）
- Material-UI / Tailwind CSS（UI 框架）

## 开发指南

查看 [开发环境搭建指南](../../docs/guides/DEVELOPMENT_SETUP.md) 了解如何设置开发环境。
