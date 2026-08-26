# Hash Tools 架构文档

## 项目概述

Hash Tools 是一个跨平台的文件哈希计算器和 PDF 数字签名验证工具，特别针对国密 SM3withSM2 算法提供完整支持。

## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    Hash Tools Application                    │
│                    (iced GUI Framework)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   File Hasher   │  │  PDF Signature  │  │    HTML     │ │
│  │  (7 algorithms) │  │    Verifier     │  │   Export    │ │
│  └────────┬────────┘  └────────┬────────┘  └──────┬──────┘ │
│           │                    │                  │         │
├───────────┴────────────────────┴──────────────────┴─────────┤
│                     pdf_signature.rs                         │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────────────┐ │
│  │ ByteRange │ │  PKCS#7   │ │    SM2    │ │  Algorithm   │ │
│  │  Parser   │ │ DER/BER   │ │ Verifier  │ │  Detector    │ │
│  └───────────┘ └───────────┘ └───────────┘ └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    External Crates                           │
│  lopdf │ cms │ asn1-rs │ libsm │ sha2 │ tera │ image       │
└─────────────────────────────────────────────────────────────┘
```

## 目录结构

```
hash_tools/
├── src/
│   ├── main.rs              # GUI 应用入口 + 导出功能
│   ├── hash_logic.rs        # 7 种哈希算法实现
│   ├── pdf_signature.rs     # PDF 签名提取与验证核心
│   ├── style.rs             # UI 样式定义
│   └── icons.rs             # SVG 图标资源
├── templates/
│   └── diagnostics_report.html  # HTML 导出模板 (tera)
├── assets/
│   ├── icon.png             # 应用图标 (源)
│   ├── icon.ico             # Windows 图标
│   └── app.manifest         # Windows UAC 清单
├── scripts/
│   ├── create_code_signing_cert.ps1  # Windows 代码签名
│   └── setup_windows_icon.ps1        # ICO 生成脚本
├── docs/
│   ├── product_overview.html         # 产品介绍 (管理层)
│   ├── technical_implementation.html # 技术文档 (开发者)
│   └── hash_verification_guide.html  # 哈希验证指南
├── build.rs                 # Windows 资源嵌入
├── Cargo.toml               # 依赖配置
└── README.md                # 项目说明
```

## 核心模块

### 1. pdf_signature.rs

**职责**：PDF 签名提取与验证

**关键结构**：
- `SignatureInfo` - 签名元数据
- `SignatureVerificationResult` - 验证结果
- `SignatureAlgorithm` - 算法枚举

**核心方法**：
- `verify_signature()` - 完整验证流程
- `extract_message_digest()` - DER/BER 双模式提取
- `extract_sm2_public_key()` - 证书公钥提取
- `get_display_name()` - 智能签名者名称

### 2. hash_logic.rs

**职责**：多算法哈希计算

**支持算法**：
- SM3 (国密)
- SHA-256, SHA-512
- SHA3-256, SHA3-512
- SHA-1, MD5
- BLAKE3

### 3. main.rs

**职责**：GUI 应用 + 诊断导出

**关键功能**：
- 拖放文件处理
- 实时签名验证
- HTML 报告生成 (tera)

## 验证流程

```
1. 算法检测 (三级优先级)
   ├─ PDF SubFilter
   ├─ PKCS#7 OID
   └─ Hash 长度推断

2. 编码适配 (自动降级)
   ├─ DER 解析 (cms crate)
   └─ BER 二进制搜索 (fallback)

3. 哈希验证
   └─ 计算值 vs messageDigest

4. 签名验证 (SM2)
   └─ sm2_verify(pubkey, sig, attrs)
```

## 依赖清单

| Crate | 用途 |
|-------|------|
| lopdf | PDF 解析 |
| cms | PKCS#7 DER |
| asn1-rs | BER 解析 |
| libsm | SM2/SM3 |
| iced | GUI |
| tera | HTML 模板 |
| image | 图标加载 |
