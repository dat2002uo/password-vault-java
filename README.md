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
