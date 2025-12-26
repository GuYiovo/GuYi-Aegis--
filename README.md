README.md
# 🛡️ GuYi Aegis Pro - 企业级验证管理系统

> **📚 官方文档**: [**https://aegis.可爱.top/**](https://aegis.可爱.top/)  
> *(提示：v14.0 Enterprise 架构已全新升级，为了获得最佳的对接体验，请务必优先查阅官方文档)*

<p align="left">
  <a href="https://aegis.可爱.top/">
    <img src="https://img.shields.io/badge/Version-v14.0_Enterprise-6366f1.svg?style=flat-square&logo=github&logoColor=white" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/Database-MySQL_High_Concurrency-007AFF.svg?style=flat-square&logo=mysql&logoColor=white" alt="Database">
  <img src="https://img.shields.io/badge/Architecture-Headless_API-34C759.svg?style=flat-square&logo=serverless&logoColor=white" alt="Architecture">
  <img src="https://img.shields.io/badge/License-Proprietary-FF3B30.svg?style=flat-square" alt="License">
</p>

---
## 📖 产品概述

**GuYi Aegis Pro v14.0 Enterprise** 是一套专为独立开发者与中小微企业打造的 **高并发、低延迟** 软件授权分发解决方案。

v14.0 版本是一次彻底的架构重构。为了追求极致的性能与轻量化，我们**移除了内置的 Web 端卡密验证页面**，全面转向 **纯 API 驱动 (Headless) 架构**。系统弃用了 SQLite，转而采用高性能的 **MySQL 数据库架构**，配合 **App Key 多租户隔离** 与 **云变量 2.0 引擎**，专注于为桌面软件、APP、插件等客户端提供毫秒级的鉴权服务。

---

## 💎 核心特性 (Core Features)

### 🔐 1. 金融级安全防护体系
构建了从网络层到应用层的多维防御矩阵，确保业务数据零泄露。

-   **网络安全响应头**: `config.php` 自动设置 `X-Frame-Options` (防点击劫持)、`X-XSS-Protection` (防XSS)、`X-Content-Type-Options` (防MIME嗅探)、`Referrer-Policy`，提升HTTP安全基线。
-   **CSRF 全局防护**: 后台管理操作 (`cards.php`) 全程启用 Token 令牌校验，防止跨站请求伪造。配合数据层面的 PDO 预处理，有效阻断 SQL 注入与越权操作。
-   **强制安全合规**: 首次登录强制要求管理员重置默认密码，符合等保安全规范，提升系统初始安全性。
-   **会话安全强化**:
    -   管理员登录 (`cards.php`) 引入 `HMAC-SHA256` 签名的 `admin_trust` Cookie 实现更安全的自动登录。该 Cookie 绑定 `User-Agent` 和管理员密码哈希指纹，密码修改后旧 Cookie 立即失效。
    -   **API 鉴权风控**: `database.php` 中的 `verifyCard` 逻辑对卡密状态（未激活、已激活、已封禁）、有效期（精确到秒）和设备绑定情况进行严格判断，防止多设备滥用和过期使用。
-   **后台防爆破**: `cards.php` 在管理员登录失败时，引入 `usleep()` 延迟机制，抵御暴力破解攻击。

### 🏢 2. 多租户 SaaS 隔离架构
一套系统即可支撑庞大的软件矩阵，实现集中化管理与数据隔离。

-   **App Key 租户隔离**: `database.php` 支持无限添加应用，每个应用拥有独立的 `App Key`。验证核心 (`verifyCard`) 强制要求 `App Key` 进行卡密数据、设备绑定、云变量的物理级逻辑隔离。
-   **纯 API 鉴权模式**: `Verifyfile/api.php` 是客户端交互的唯一入口。支持针对特定应用进行鉴权，同时提供“免卡密”模式，仅凭 AppKey 即可获取公共变量。
-   **实时封禁控制台**: `cards.php` 后台支持毫秒级的卡密阻断 (`ban_card`) 与解封 (`unban_card`) 操作，异常情况（如设备异常或滥用）可立即处置。
-   **应用状态管理**: `cards.php` 可启用/禁用应用，禁用状态下的应用无法通过 API 进行验证，实现细粒度的应用管控。

### ☁️ 3. 云变量引擎
无需更新软件即可动态控制内容，支持 **Upsert** 智能写入逻辑。

-   **独立变量表**: `database.php` 维护 `app_variables` 表，为每个应用存储独立的键值对变量。
-   **公开变量 (Public)**: `Verifyfile/api.php` 允许客户端无需卡密登录，仅凭 `App Key` 即可获取勾选为“公开”的变量（适用于全局公告、版本检测信息等）。
-   **私有变量 (Private)**: `Verifyfile/api.php` 在卡密验证通过后，与卡密有效期等信息一同下发所有变量（包括私有变量），适用于 VIP 下载链接、专用配置等敏感资源。
-   **灵活配置**: `cards.php` 后台可为每个应用添加、删除和管理专属云变量，并设置其公开/私有权限。

### ⚡ 4. 高并发 MySQL 内核
基于 MySQL InnoDB 引擎的深度优化，确保数据操作的原子性与高可用性。

-   **MySQL InnoDB 优化**: `database.php` 全面适配 MySQL，所有数据表均使用 `ENGINE=InnoDB`，支持行级锁和高并发事务处理。
-   **事务一致性保障**: 在批量操作 (如 `batchUnbindCards`, `batchAddTime`) 中使用数据库事务 (`beginTransaction`, `commit`, `rollBack`) 机制，确保数据在高并发场景下的绝对一致性。
-   **智能风控**: `database.php` 的 `verifyCard` 逻辑自动计算设备指纹 (Device Hash)。系统支持 `database.php` 中的 `cleanupExpiredDevices` 定期清理过期设备，后台管理 (`cards.php`) 支持一键解绑设备 (`batch_unbind`)。
-   **自动安装引导**: 提供 `install.php` 安装向导，自动检测 PHP 环境扩展，引导用户配置数据库连接，并自动生成安全的 `config.php` 配置文件。

### 👨‍💻 5. 极致开发者体验 (DX)
-   **RESTful API**: `Verifyfile/api.php` 提供标准化的 JSON 接口设计，方便各类客户端集成，返回 `code`, `msg`, `data` 结构。
-   **Headless 架构**: 移除前端 UI 依赖，系统体积更小，响应更快，无需再为前端兼容性烦恼，专注后端鉴权逻辑。
-   **多语言示例**: 官方文档 (aegis.可爱.top) 提供 **Python, Java, C#, Go, Node.js, EPL** 等 10+ 种主流语言的 Copy-Paste Ready 调用代码，加速开发进程。
-   **标准环境支持**: 完美支持 Nginx/Apache + PHP 7.4+ + MySQL 5.7/8.0 生产环境。

---

## 📂 部署架构与目录

v14.0 采用纯 API 架构与 MySQL 存储，目录结构更加精简。请确保 Web 根目录可写以便安装程序生成配置文件：

```text
/ (Web Root)
├── Verifyfile/           # [核心] 后端 API 目录
│   ├── captcha.php       # 后台登录验证码生成接口
│   └── api.php           # [重要] 核心 API 接口 (客户端对接的唯一入口)
├── backend/              # 后台管理界面的静态资源目录
│   └── logo.png          # 系统 Logo 图片
├── assets/               # 后台通用资源目录
│   ├── css/              # 样式文件
│   └── js/               # JavaScript 文件
├── install.php           # [新增] 系统安装向导 (安装后建议删除)
├── cards.php             # 后台管理系统主控制台 (管理员登录入口)
├── config.php            # 系统核心配置文件 (包含数据库连接信息，安装后自动生成)
└── database.php          # 数据库操作核心类 (封装 PDO_MySQL 所有交互逻辑)

官方群1077643184
Copyright © 2026 GuYi Aegis Pro. All Rights Reserved.
