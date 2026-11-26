# Password-Vault-Java
A command-line password vault implemented in Java.

## Tech Stack
- Java 17
- AES-256-GCM AEAD authenticated encryption
- PBKDF2-HMAC-SHA256 for key derivation

## Features
- Create, read, update and delete stored passwords; export & load encrypted vault files
- Use header metadata as AAD to verify integrity, against tampering and downgrade attacks
- Generate fresh salt and nonce on every save to avoid GCM nonce reuse vulnerability
- Secure error handling: keep in-memory data for invalid input; clear sensitive memory on decryption failure
- Custom JSON parser for input validation, with sensitive byte array cleanup

## Usage
Compile and run the main class. Supported commands:
`create / set / get / remove / dump / load`

## Note
This is for learning cryptographic security mechanisms, not for production use.

Chinese version:
# Password-Vault-Java
Java实现的命令行密码保险库。

## 技术栈
- Java 17
- AES‑256‑GCM AEAD认证加密
- PBKDF2‑HMAC‑SHA256密钥派生

## 项目功能
- 密码增删改查、导出vault密文文件、加载解密
- 文件头部元数据作为AAD完整性校验，防御篡改、降级攻击
- 每次保存生成全新salt、nonce，规避GCM nonce复用漏洞
- 安全错误语义：非法输入保留内存；解密失败清空敏感内存
- 手写JSON解析器，做输入校验；敏感字节数组内存清零

## 运行
编译后运行主类，支持create / set / get / remove / dump / load指令。

## 说明
本项目仅用于学习密码学安全机制。
