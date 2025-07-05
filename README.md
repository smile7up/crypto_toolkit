# Crypto Toolkit - Dify 插件

**Crypto Toolkit** 是一个为 Dify 设计的功能强大的插件，它集成了一系列常用的加密、解密、编码和哈希工具。无论你是需要保护敏感数据，还是处理网络数据格式，这个工具包都能提供便捷、可靠的支持。

## ✨ 功能概览

本插件遵循 Dify 的最佳实践，将每个功能封装为独立的工具，确保了使用的灵活性和清晰的架构。

-   **编码/解码**:
    -   `Base64 Encode / Decode`: 对数据进行 Base64 编码和解码。
    -   `URL Encode / Decode`: 对 URL 字符串进行编码和解码。
-   **对称加密**:
    -   `AES Encrypt (GCM)`: 使用行业推荐的 AES-GCM 模式进行认证加密。
    -   `AES Decrypt (GCM)`: 解密并验证由本插件加密的数据。
-   **哈希/摘要**:
    -   `SHA-256 Hash`: 计算数据的 SHA-256 哈希值，用于数据完整性校验。
    -   `MD5 Hash`: 计算数据的 MD5 哈希值，用于文件校验等非安全场景。
-   **辅助工具**:
    -   `Secure Key Generator`: 生成适用于 AES 加密的密码学安全随机密钥。

## 🚀 安装与使用

1.  **下载插件**: 下载最新的 `crypto_toolkit.zip` 压缩包。
2.  **上传插件**: 登录你的 Dify 平台，导航至 **工作室 > 工具**，点击 **创建工具** 并选择 **从 Zip 文件上传**。
3.  **选择插件**: 上传 `crypto_toolkit.zip` 文件。
4.  **启用插件**: 在你的 AI 应用中，进入 **提示词编排 > 工具**，点击 **添加**，然后选择 "Crypto Toolkit" 即可开始使用。

## 🛠️ 工具详解

#### 1. Secure Key Generator
-   **用途**: 创建一个用于 AES 加密的强随机密钥。这是进行 AES 加密前的**第一步**。
-   **输入**:
    -   `Key Size`: 选择密钥长度 (128, 192, 或 256 位)。推荐使用 `256-bit` 以获得最高安全性。
-   **输出**:
    -   `generated_key`: 一个符合所选长度的随机字符串密钥。

#### 2. AES Encrypt (GCM)
-   **用途**: 加密你的文本数据。
-   **输入**:
    -   `Input String`: 你想要加密的原始文本。
    -   `Encryption Key`: 从 `Secure Key Generator` 工具获得的密钥。
-   **输出**:
    -   `encrypted_data`: 一个包含密文、nonce 和认证标签的 JSON 对象。**请务必完整保存此 JSON 对象**，解密时需要用到。

#### 3. AES Decrypt (GCM)
-   **用途**: 解密数据并验证其未被篡改。
-   **输入**:
    -   `Encrypted Data (JSON)`: 从 `AES Encrypt` 工具获得的完整 JSON 输出。
    -   `Decryption Key`: 加密时使用的**同一个**密钥。
-   **输出**:
    -   `decrypted_string`: 解密后的原始文本。

#### 4. Base64 Encode / Decode
-   **用途**: 在需要通过文本协议传输二进制数据时使用。
-   **输入**:
    -   `Input String`: 需要编码或解码的字符串。
-   **输出**:
    -   编码或解码后的字符串。

#### 5. URL Encode / Decode
-   **用途**: 处理 URL 中的特殊字符。
-   **输入**:
    -   `Input String`: 需要编码或解码的 URL 或其一部分。
-   **输出**:
    -   编码或解码后的字符串。

#### 6. SHA-256 / MD5 Hash
-   **用途**: 计算字符串的哈希值，主要用于验证数据完整性。
-   **输入**:
    -   `Input String`: 需要计算哈希的字符串。
-   **输出**:
    -   `hash_string`: 计算出的哈希值（十六进制格式）。

## 💡 典型用例：安全地加密和解密一条消息

1.  **生成密钥**: 调用 `Secure Key Generator` 工具，选择 `256-bit`，获得一个32位的密钥，例如 `p8sA...z9B`。
2.  **加密消息**: 调用 `AES Encrypt (GCM)` 工具。
    -   `Input String`: `This is a secret message.`
    -   `Encryption Key`: `p8sA...z9B`
    -   获得输出 `encrypted_data`: `{"ciphertext": "...", "nonce": "...", "tag": "..."}`
3.  **解密消息**: 调用 `AES Decrypt (GCM)` 工具。
    -   `Encrypted Data (JSON)`: `{"ciphertext": "...", "nonce": "...", "tag": "..."}`
    -   `Decryption Key`: `p8sA...z9B`
    -   获得输出 `decrypted_string`: `This is a secret message.`

## ⚠️ 安全注意事项

-   **密钥管理**: AES 加密的安全性完全取决于密钥的保密性。请妥善保管你的密钥，切勿在不安全的环境中传输或存储。
-   **算法选择**:
    -   对于需要**保密性**的场景，请使用 `AES Encrypt`。
    -   对于需要**验证数据完整性**的场景，请使用 `SHA-256 Hash`。
    -   `MD5 Hash` 存在已知的碰撞漏洞，不应用于安全敏感的场景（如密码存储），仅用于文件校验和等传统用途。

---
