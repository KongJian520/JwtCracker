# JWT Cracker

`喜欢的话点一个Star吧~`

### 主要功能

* **GUI 模式**:
    * **直观的用户界面**：提供易于使用的 GUI，用户可以通过勾选框和输入框来配置爆破选项。
    * **可定制字符集**：支持使用预设的字符集（小写字母、大写字母、数字、特殊字符）进行组合，或使用自定义字符集进行爆破。
    * **长度控制**：可以设置爆破密钥的最小和最大长度。
    * **JWT 令牌解码/编码**：可以自动解码输入的 JWT 令牌，并分别显示其头部（Header）和载荷（Payload）。找到密钥后，会用新密钥重新对令牌进行签名。
* **CLI 模式**:
    * **命令行参数**：支持通过命令行参数指定要破解的 JWT 令牌、最小长度和最大长度。
    * **进度条**：在终端中显示一个动态的进度条，实时反馈爆破进度和当前正在尝试的密钥。
  * **动态视觉反馈**：~~ 纯粹是为了伯君一笑 ~~。

### 优势

* **并行处理**：利用 `rayon` 库进行并行化处理，以提高破解速度。
* **极小的内存占用**：通过迭代器生成密钥组合，避免了将所有组合预先存储在内存中。CLI模式下仅占用2M内存

### 如何使用

#### 1. 构建项目

请确保电脑上有 Rust 编程环境。

```sh
git clone [https://github.com/KongJian520/JwtCracker.git](https://github.com/KongJian520/JwtCracker.git)
cd JwtCracker
cargo build --release
```

#### 2\. GUI 模式

构建完成后，直接运行可执行文件即可启动 GUI 界面。

```sh
./target/release/JwtCrackerGUI
```

#### 3\. CLI 模式

通过命令行参数指定要破解的 JWT 令牌和长度范围。

```sh
./target/release/JwtCrackerCLI -t <要破解的JWT令牌> -m <最小长度> -x <最大长度>
```

**示例**:
`Secret是1234`

```sh
./target/release/JwtCrackerCLI -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.iQunLC9JL7hQ0nOGeeUGjpoxi2aE5F4V-Libb7Vqulw" -m 1 -x 10
```

### 依赖项

该项目使用了以下 Rust crates：

* `clap`：用于处理命令行参数。
* `eframe` 和 `egui`：用于构建跨平台 GUI。
* `egui_extras`：提供 egui 的额外功能，例如代码高亮。
* `crossbeam-channel`：用于线程间通信，实现任务的停止功能。
* `rayon`：用于并行化处理，提高破解效率。
* `base64`：用于 Base64 编解码。
* `serde_json`：用于处理 JSON 数据。
* `jsonwebtoken`：用于处理 JWT 令牌。
* `hmac` 和 `sha2`：用于 HMAC-SHA256 签名验证。
* `indicatif`：在 CLI 模式下显示进度条。
* `rand`：用于生成随机数，以随机选择进度条样式。
* `epaint`: 用于字体加载。

-----

### 免责声明

<details>
此软件的开发和发布仅用于教育和研究目的。其旨在帮助安全专业人员和开发人员理解 JWT（JSON Web
Tokens）的工作原理和潜在的安全漏洞，以便更好地保护他们的应用程序。

**用户责任**

您理解并同意，使用本软件的风险由您自行承担。您有责任确保您的所有行为都符合适用的法律法规。本软件不得用于任何非法或未经授权的活动，包括但不限于未经授权地访问、修改或破坏任何系统、数据或网络。

**无担保**
本软件按“原样”提供，不附带任何形式的明示或暗示保证，包括但不限于适销性、特定用途适用性或非侵权性的保证。开发者不保证本软件的功能将满足您的要求，或者其运行将不间断、无错误或无病毒。

**责任限制**

在任何情况下，开发者均不对因使用或无法使用本软件而引起的任何直接、间接、附带、特殊、惩罚性或后果性损害（包括但不限于利润损失、数据丢失或业务中断）承担责任，即使开发者已被告知此类损害的可能性。

通过使用本软件，您即表示已阅读并理解本免责声明的所有条款，并同意遵守。如果您不同意这些条款，请勿使用本软件。

</details>

