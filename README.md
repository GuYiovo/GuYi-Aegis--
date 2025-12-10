# 🛡️ GuYi Aegis Pro - 企业级验证管理系统

> **📚 官方文档**: [**https://aegis.可爱.top/**](https://aegis.可爱.top/)  
> *(提示：v7.0 Enterprise 架构已全新升级，为了获得最佳的对接体验，请务必优先查阅官方文档)*

<p align="left">
  <a href="https://aegis.可爱.top/">
    <img src="https://img.shields.io/badge/Version-v7.0_Enterprise-6366f1.svg?style=flat-square&logo=github&logoColor=white" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/Database-SQLite3_Accelerated-007AFF.svg?style=flat-square&logo=sqlite&logoColor=white" alt="Database">
  <img src="https://img.shields.io/badge/Security-Enterprise_Grade-34C759.svg?style=flat-square&logo=security-scorecard&logoColor=white" alt="Security">
  <img src="https://img.shields.io/badge/License-Proprietary-FF3B30.svg?style=flat-square" alt="License">
</p>

---

## 📖 产品概述

**GuYi Aegis Pro v7.0 Enterprise** 是一套专为独立开发者与中小微企业打造的 **高可用、低代码** 软件授权分发解决方案。

v7.0 版本彻底移除了 MySQL 依赖，采用独家优化的 **SQLite3 文件数据库架构**，实现了读写性能 300% 的提升与“零配置”秒级部署。系统内置 **App Key 多租户隔离**、**自愈合内核** 以及 **云变量 2.0 引擎**，为您的软件资产提供固若金汤的保护与灵活的分发控制。

---

## 💎 核心特性 (Core Features)

### 🔐 1. 金融级安全防护体系
构建了从网络层到应用层的多维防御矩阵，确保业务数据零泄露。

- **CSRF 全局防护**: 全站启用 Token 令牌校验，配合输入数据 PDO 预处理，彻底阻断 SQL 注入与越权操作。
- **强制安全合规**: 首次登录强制要求管理员重置默认密码，符合等保安全规范。
- **算法升级**: 优化卡密生成算法，移除易混淆字符并增强随机数熵值；会话采用 `HMAC-SHA256` 签名防止劫持。
- **API 熔断与限流**: 内置基于文件锁的 IP 速率限制算法，有效抵御暴力破解与高频扫描。

### 🏢 2. 多租户 SaaS 隔离架构
一套系统即可支撑庞大的软件矩阵，实现集中化管理与数据隔离。

- **App Key 租户隔离**: 支持无限添加应用，通过 `App Key` 实现卡密数据、设备绑定、黑名单的物理级逻辑隔离。
- **灵活鉴权模式**: API 接口支持定向应用鉴权，不同软件之间的用户互不干扰。
- **实时封禁控制台**: 支持毫秒级的卡密阻断与解封操作，异常情况立即处置。

### ☁️ 3. 云变量 2.0 引擎 (New)
不更新软件即可动态控制内容，支持 **Upsert** 智能写入逻辑。

- **公开变量 (Public)**: 无需登录即可获取（如：全局公告、版本检测），仅需验证 `App Key`。
- **私有变量 (Private)**: 仅在卡密验证通过后下发（如：VIP下载链接、专用配置），保护核心资源。

### ⚡ 4. 高性能自愈内核
基于 SQLite3 的深度优化，确保数据操作的原子性与高可用性。

- **Database Self-Healing**: 独创“防白屏”机制，系统启动时自动检测并修复异常表结构。
- **连接池优化**: 优化了高并发下的文件锁竞争问题，单节点并发处理能力大幅提升。
- **智能风控**: 自动计算设备指纹 (Device Hash)，支持自动清洗过期设备与强制干预。

### 👨‍💻 5. 极致开发者体验 (DX)
- **RESTful API**: 标准化的 JSON 接口设计。
- **多语言示例**: 官方文档提供 **Python, Java, C#, Go, Node.js, EPL** 等 10+ 种主流语言的 Copy-Paste Ready 调用代码。

---

## 📂 部署架构与目录

v7.0 采用轻量化结构，请确保 `/data` 目录拥有 **777 读写权限**：

```text
/ (Web Root)
├── auth_check.php      # [Core] 会话鉴权中间件
├── cards.php           # [Core] 管理后台控制器 (建议重命名以隐藏入口)
├── config.php          # [Config] 全局配置文件
├── database.php        # [Model] 数据库核心类 (ACID事务支持)
├── index.php           # [View] 用户前台入口
├── verify.php          # [Controller] 前端验证逻辑
├── index1.php          # [View] 验证成功落地页
│
├── Verifyfile/         # [Module] 外部接口模块
│   ├── api.php         # 客户端统一接入 API
│   └── captcha.php     # 图形验证码生成器
│
├── backend/            # [Assets] 静态资源库
│   └── logo.png        # 品牌标识
│
└── data/               # [Storage] 数据库目录 (★必须 777 权限)
    ├── cards.db        # SQLite 数据库 (自动创建/自愈)
    └── .htaccess       # Apache 防下载安全规则
```

🚀 v7.0 Enterprise 更新日志摘要
- **[架构]** 底层迁移至 SQLite3，性能提升 300%，移除 MySQL 依赖。
- **[功能]** 新增 App Key 多租户系统，支持无限应用隔离。
- **[功能]** 云变量 2.0 上线，支持公开/私有双重作用域。
- **[安全]** 全局 CSRF 防护与 PDO 预处理重构。
- **[体验]** 文档中心重构，新增 10+ 种语言接入示例。

Copyright © 2026 GuYi Aegis Pro. All Rights Reserved.