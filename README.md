# 🛡️ GuYi Aegis Pro - 企业级验证管理系统

> **📚 官方文档**: [**https://aegis.可爱.top/**](https://aegis.可爱.top/)  
> *(提示：为了获得最佳的对接体验与技术支持，请务必优先查阅官方文档)*

<p align="left">
  <a href="https://aegis.可爱.top/">
    <img src="https://img.shields.io/badge/Documentation-官方文档-007AFF.svg?style=flat-square&logo=read-the-docs&logoColor=white" alt="Documentation">
  </a>
  <img src="https://img.shields.io/badge/Architecture-SaaS_Ready-FF9500.svg?style=flat-square&logo=amazonaws&logoColor=white" alt="SaaS Ready">
  <img src="https://img.shields.io/badge/Security-Enterprise_Grade-34C759.svg?style=flat-square&logo=security-scorecard&logoColor=white" alt="Security">
  <img src="https://img.shields.io/badge/License-Proprietary-FF3B30.svg?style=flat-square" alt="License">
</p>

---

## 📖 产品概述

**GuYi Aegis Pro** 是一套专为独立开发者与中小微企业打造的 **高可用、低代码** 软件授权分发解决方案。

摒弃了传统 MySQL 数据库的笨重部署方式，系统基于轻量级架构重构，实现了**“上传即用”**的极速交付体验。通过内置的多租户隔离技术、全链路设备指纹风控以及金融级的数据加密机制，为您的软件资产提供固若金汤的保护。

---

## 💎 核心特性 (Core Features)

### 🔐 1. 金融级安全防护体系
构建了从网络层到应用层的多维防御矩阵，确保业务数据零泄露。

- **会话无感防护**: 采用 `HMAC-SHA256` 算法对 Cookie 进行数字签名，配合 `User-Agent` 强绑定机制，彻底杜绝会话劫持与重放攻击。
- **主动防御机制**: 全局部署 `CSRF Token` 令牌校验，内置 XSS 跨站脚本过滤，并在 HTTP 头强制启用 `X-Frame-Options` 与 `No-Sniff` 策略。
- **API 熔断与限流**: 内置基于文件锁的 IP 速率限制算法 (Rate Limiting)，有效抵御暴力破解与高频扫描，保障接口高可用。
- **前端防逆向**: 登录页集成 JS 反调试模块（禁用 F12、右键及快捷键），增加非法破解成本。

### 🏢 2. 多租户 SaaS 隔离架构
一套系统即可支撑庞大的软件矩阵，实现集中化管理与数据隔离。

- **多应用接入**: 支持无限添加应用（软件/脚本），每个应用自动分配独立的 `App Key`，业务逻辑互不干扰。
- **灵活鉴权**: API 接口支持定向应用鉴权与通用卡池鉴权的双模自动切换，适配复杂的业务场景。
- **数据隔离**: 数据库层面实现逻辑隔离，确保不同应用的卡密、日志与设备数据归属清晰。

### ⚡ 3. 高性能事务处理引擎
基于 PDO 预处理与 SQLite 事务机制，确保数据操作的原子性与一致性 (ACID)。

- **批量并发处理**: 支持毫秒级的批量制卡、批量加时、批量解绑与批量导出操作，轻松应对万级数据吞吐。
- **智能设备风控**: 
  - **指纹追踪**: 自动计算设备唯一标识 (Device Hash)，支持单设备绑定模式。
  - **自动清洗**: 智能识别并自动解绑过期设备，释放系统资源。
  - **强制干预**: 管理员可在后台实时阻断异常设备的访问权限。

### 📊 4. 可视化商业智能 (BI)
不仅仅是管理工具，更是您的业务决策辅助中心。

- **实时仪表盘**: 图形化展示库存水位、活跃设备趋势、卡类型分布占比，业务健康度一目了然。
- **全链路审计日志**: 详细记录每一次 API 调用的时间、来源 IP、设备指纹、所属应用及鉴权结果，为故障排查与安全审计提供可追溯证据。
- **精美 UI 设计**: 管理后台采用现代化响应式布局，前台登录页采用 Glassmorphism (毛玻璃) 拟态风格，提升品牌形象。

---

## 📂 部署架构与目录

为确保系统核心功能的正常加载，请严格遵守以下文件结构标准：

```text
/ (Web Root)
├── auth_check.php      # [Core] 会话鉴权中间件
├── cards.php           # [Core] 管理后台控制器
├── config.php          # [Config] 全局配置文件 (需修改密钥)
├── database.php        # [Model] 数据库ORM层
├── index.php           # [View] 用户前台入口
├── verify.php          # [Controller] 前端验证逻辑
├── index1.php          # [View] 验证成功落地页 (需自建)
│
├── Verifyfile/         # [Module] 外部接口模块
│   ├── api.php         # 客户端对接 API
│   └── captcha.php     # 图形验证码生成器
│
├── backend/            # [Assets] 静态资源库
│   └── logo.png        # 品牌标识
│
└── data/               # [Storage] 数据持久化层 (自动生成)
    ├── cards.db        # SQLite 数据文件
    └── .htaccess       # Apache/LS 安全规则文件
```

---

## 🚀 快速部署指南

1. **环境准备**
   - 运行环境: PHP 7.4 - 8.2 (推荐 8.0，兼顾性能与兼容性)
   - Web 服务器: Nginx / Apache / OpenLiteSpeed
   - 必要扩展:
     - `pdo_sqlite` (核心依赖)
     - `gd` (图形处理)
     - `json` (接口交互)

2. **初始化步骤**
   - **代码部署**: 将完整源码包上传至服务器 Web 根目录。
   - **权限授予**: 赋予根目录读写权限 (Linux: `chmod -R 755 .`)，系统首次运行将自动初始化 `data/` 目录与数据库结构。
   - **安全加固 (Critical)**:
     - 编辑 `config.php` 文件。
     - 将 `define('SYS_SECRET', '...');` 修改为一段高强度随机字符串（建议 32 位以上）。

3. **后台登录**:
   - 访问地址: `http://your-domain.com/cards.php`
   - 初始凭证: 用户名 `admin` / 密码 `admin123`
   - **安全提示**: 首次登录后请务必在“系统设置”模块重置管理员密码。

---

## 🔌 开发者 API 对接规范

本系统提供符合 RESTful 风格的 JSON 标准接口，支持易语言、Python、C#、Lua 等全语言客户端接入。

- **Endpoint**: `http://your-domain.com/Verifyfile/api.php`
- **Method**: POST (Recommended)
- **Content-Type**: `application/json` 或 `application/x-www-form-urlencoded`

### 1. 请求参数定义

| 参数字段 | 类型   | 必填 | 描述                                   |
| :------- | :----- | :--- | :------------------------------------- |
| `card` (or `key`) | String | ✅   | 用户激活码/卡密                       |
| `device`          | String | ❌   | 客户端机器码 (留空则由服务端基于 IP+UA 混合计算) |
| `app_key`         | String | ❌   | **应用密钥** (多应用模式必填，在后台[应用接入]处获取) |

### 2. 响应报文示例

✅ **HTTP 200 OK (验证通过)**

```json
{
    "code": 200,
    "msg": "OK",
    "data": {
        "status": "active",
        "expire_time": "2025-12-31 23:59:59",
        "remaining_seconds": 31536000,
        "device_id": "a1b2c3d4e5f6..."
    }
}
```

⛔ **HTTP 403 Forbidden (业务拒绝)**

```json
{
    "code": 403,
    "msg": "卡密已过期 / 设备指纹不匹配",
    "data": null
}
```

---

## ⚠️ 运维安全最佳实践

- **后台入口隐蔽**: 建议将 `cards.php` 重命名为随机字符文件（如 `admin_sys_v2.php`），降低被扫描爆破风险。
- **HTTPS 全站加密**: 生产环境必须启用 SSL 证书，防止卡密在网络传输层被中间人嗅探。
- **冷备份策略**: 由于采用单文件数据库架构，建议定期下载 `/data/cards.db` 至本地进行冷备份。
- **Nginx 访问控制**: 若使用 Nginx 服务器，请在配置块中添加如下规则，禁止外部直接下载数据库文件：

```nginx
location ~ ^/data/.*\.(db|htaccess)$ {
    deny all;
    return 403;
}
```

Copyright © 2026 GuYi Aegis Pro. All Rights Reserved.
