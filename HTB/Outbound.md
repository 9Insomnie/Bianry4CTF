# HackTheBox - Outbound 靶机通关笔记

## 0x00 侦察阶段

### 0x01 初始凭证

| 角色 | 用户名 | 密码         | 备注         |
|------|--------|--------------|--------------|
| 初始 | tyler  | LhKL1o9Nm3X2 | Webmail 账户 |

### 0x02 端口扫描发现

HTTP 流量被无缝重定向至 `http://mail.outbound.htb/`

## 0x10 Web 层渗透

### 0x11 Roundcube Webmail 接口

80 端口部署了 Roundcube Webmail 实例，可使用预设凭证 `tyler / LhKL1o9Nm3X2` 登录：

此配置与 [DarkCorp](https://4xura.com/ctf/htb/htb-writeup-darkcorp/#toc-head-3) 案例相似（当时版本为 `1.6.7`）。本次目标使用升级版本：`1.6.10`，并加载了高价值插件——文件压缩、文件系统访问和上传功能，攻击面显著扩大， ripe for exploitation。

### 0x12 CVE-2025-49113 漏洞利用

#### 认证后 RCE

以上传为核心的插件是明显的危险信号——典型的基于文件上传的 RCE。快速侦察确认：[CVE-2025-49113](https://nvd.nist.gov/vuln/detail/CVE-2025-49113) 完全匹配。

这是教科书式的**认证后远程代码执行**，攻击流程极其清晰：

1. **登录**：使用有效 Roundcube 凭证
2. **滥用文件上传**：篡改 **`_from`** 参数并注入序列化 Payload
3. **触发反序列化**：后端反序列化用户可控数据，通过构造的 PHP 对象执行任意代码

在邮件添加附件时暴露了上传端点：

网上已有多个 PoC，包括定制的 [Metasploit 模块](https://www.cvedetails.com/cve/CVE-2025-49113)：`roundcube_auth_rce_cve_2025_49113`，即插即用。

#### PHP 反序列化原理

[OffSec 研究](https://www.offsec.com/blog/cve-2025-49113/) 提供了详尽分析——经典的 PHP 反序列化漏洞，通过细致的代码审计发现。一个月前刚披露，已被武器化。

GitHub 上有可用的 [PoC](https://github.com/hakaioffsec/CVE-2025-49113-exploit)——即插即用。

启动监听器后发送 Payload：

执行顺利：

成功获取初始 shell，用户为 `www-data`（Web 服务进程用户）。

## 0x20 用户权限提升

### 0x21 配置文件侦察

获得 `www-data` 权限后，立即进行配置文件侦察。

发现 `/var/www/html/roundcube/config/config.inc.php`：

**数据库凭证**：

**IMAP/SMTP 主机信息**：

邮件服务状态检查：

`dovecot`（IMAP 服务）和 `postfix`（SMTP 服务）均运行正常。

此外，`%u` 和 `%p` 参数表示 Roundcube**复用用户提供的凭证进行 SMTP 认证**。因此，一旦通过 RCE 或数据库转储获取用户账户，即可以其身份发送/读取邮件。

**加密密钥**：

此密钥**用于加密存储在 PHP 会话或数据库中的 IMAP 密码**。如果获得 `session` 或 `users` 表访问权限，即可**解密保存的 IMAP 密码**。

### 0x22 数据库突破

使用发现的凭证连接本地 MySQL 实例：

检查 `users` 表：

发现两个新用户：`jacob` 和 `mel`。`jacob` 显示登录失败——可能是暴力破解或凭证过期？`preferences` 字段包含无害的序列化配置（`client_hash`），不含认证信息。

由于已获取加密密钥，检查 `session` 表查看是否存在存储的 PHP 会话：

这是一段**存储的 IMAP 密码**。而我们之前已获得**DES 密钥**：

有了 `password` 字段和 `des_key`，即可**解密 IMAP 凭证**并劫持邮箱。

### 0x23 密码解密

对 `vars` 列进行 Base64 解码：

得到**PHP 序列化数组**。解析结果如下：

这是用户 `jacob` 的**经 Base64 编码的加密 IMAP 密码**。

#### 解密方法 1

Roundcube 的解密逻辑定义在 `rcube.php` 第 943 行：

```php
public function decrypt($cipher, $key = 'des_key', $base64 = true)
{
    ...

    // base64 解码
    if ($base64) {
        $cipher = base64_decode($cipher, true);
        if ($cipher === false) {
            return false;
        }
    }

    // 从配置获取 des_key
    $ckey = $this->config->get_crypto_key($key);
    // 默认为 'DES-EDE3-CBC'
    $method = $this->config->get_crypto_method();
    // 3DES 通常为 8
    $iv_size = openssl_cipher_iv_length($method);

    ...

    // IV 嵌入在密文中
    $iv = substr($cipher, 0, $iv_size);
	
    ...

    // 使用 PHP 的 `openssl_decrypt()` 解密
    $cipher = substr($cipher, $iv_size);
    $clear = openssl_decrypt($cipher, $method, $ckey, \OPENSSL_RAW_DATA, $iv, $tag);

    return $clear;
}
```

默认情况下，Roundcube 使用 **3DES (DES-EDE3-CBC)** 加密。因此只需简单修改 PHP 函数即可解密：

运行后得到：

#### 解密方法 2

搜索 Roundcube 密码解密时，发现官方 GitHub 仓库中提供了通用解密工具 [`bin/decrypt.sh`](https://github.com/roundcube/roundcubemail/blob/master/bin/decrypt.sh)：

```php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

尽管注释误导性地提到 Received 标头，但**底层的解密函数 `rcube::decrypt()` 是通用目的**，在 Roundcube 中广泛使用，与 `rcube.php` 中的定义相同。

在服务器上，该脚本位于：

可直接使用其对 Base64 编码的加密密码进行解密：

结果相同。

### 0x24 IMAP 访问与会话劫持

会话数据显示 **Jacob 收件箱中有 2 封邮件**：

凭借解密后的密码 `595mO8DmwGeD` 和已知用户名（`jacob`），我们拥有**有效的 IMAP 凭证**访问其邮箱。

在 2 封邮件中，发现密码重置邮件：

复用密码 `gY4Wr3a1evp4` 通过 SSH 以用户 `jacob` 登录：

成功获取用户 flag。

## 0x30 root 权限提升

### 0x31 Sudo 权限分析

检查 `sudo` 权限：

[`below`](https://github.com/facebookincubator/below) 是一个用 Rust 编写的 **Linux 系统 TUI 性能监控工具**，类似 `htop`，但基于 `perf` 并存储记录：

查看命令帮助手册：

值得注意的是，`sudo` 规则禁止我们使用以下参数运行任何命令：

### 0x32 CVE-2025-27591 漏洞

搜索后发现 [CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591)，与我们 `below` 的 `sudo` 权限直接相关。

`below` 0.9.0 之前的版本**以全局可写权限创建 `/var/log/below/` 目录**：

本地攻击者（非 root）可以：

仓库中的 [`logrotate.conf`](https://github.com/facebookincubator/below/blob/v0.9.0/etc/logrotate.conf)：

……确认其使用存储在 `/var/log/below/` 下的 `error_*.log` 文件。

### 0x33 写入原语

目标：**滥用 `sudo below`** 强制 root 将攻击者控制的数据写入 root 拥有的日志——即使在 `--config` 或 `--debug` 等受限标志被禁用时。

`logging.rs` 设下陷阱。在[第 35 行](https://github.com/facebookincubator/below/blob/v0.9.0/below/src/open_source/logging.rs#L35)，它使用：

此 `setup` 函数**在提供的 `path` 处打开文件**（默认为 `/var/log/below/error_*.log`）。然后内部调用 `setup_log` 向其写入日志。

> 此过程**盲目跟随符号链接**，**如果文件缺失则创建**，并**追加**内容——**符号链接竞争或预创建覆盖**成为可能。

于是我们转向 `main.rs` 并检查子命令如何调用日志器，从[第 876 行](https://github.com/facebookincubator/below/blob/v0.9.0/below/src/main.rs#L876)开始：

在众多选项中，`replay` 首次出现就提供了清晰的利用路径——以下是分解（带注释）：

```rust
fn replay(
    logger: slog::Logger,	// initialze logger instance
    errs: Receiver<Error>,
    time: String,			// user-controlled --time argument
    below_config: &BelowConfig,
    host: Option<String>,
    port: Option<u16>,
    days_adjuster: Option<String>,
    snapshot: Option<String>,
) -> Result<()> {
    // Parse user-supplied --time into a timestamp (this can fail) 
    let timestamp =
        cliutil::system_time_from_date_and_adjuster(time.as_str(), days_adjuster.as_deref())?;
    
    // If malformed (e.g., non-date input)
    // this returns Err(...) containing the "time" string.

    ...

    let model = match advance.jump_sample_to(timestamp) {
        Some(m) => m,
        // [!] If no matching snapshot sample found
        // `bail!` simply returns Err.
        None => bail!(
            "No initial sample could be found!\n\
            You may have provided a time in the future or no data was recorded during the provided time. \
            Please check your input and timezone.\n\
            If you are using remote, please make sure the below service on target host is running."
        ),
    };

    ...
    
	// No log is triggered here - but that Err is passed back to run()
    view.run()
}
```

此函数接受用户控制的 `--time` 输入并尝试解析。如果无效，它会抛出包含我们输入的错误字符串——一个日志投毒原语。

实际的日志写入发生在最后一行——`view.run()`，它包装了子命令的执行，在[第 555 行](https://github.com/facebookincubator/below/blob/v0.9.0/below/src/main.rs#L555)定义：

```rust
pub fn run<F>(
    init: init::InitToken,
    debug: bool,
    below_config: &BelowConfig,	// holds log_dir  →  "/var/log/below"
    _service: Service,
    command: F,					// closure wrapping the chosen sub-command
) -> i32
where
    F: FnOnce(init::InitToken, &BelowConfig, slog::Logger, Receiver<Error>) -> Result<()>,
{
    let (err_sender, err_receiver) = channel();
    
    // Builds the full log file path `/var/log/below/below.log`
    let log_path = below_config.log_dir.join("below.log");
    
    // [1] Exploit sink #1
    // Open the logfile with create+append, following any symlink
    let logger = logging::setup(init, log_path, debug);
    setup_log_on_panic(logger.clone());

    // Execute the chosen sub-command (e.g.,  replay())
    // Any Err returned will be caught below.
    let res = command(init, below_config, logger.clone(), err_receiver);

    match res {
        Ok(_) => 0,                                    // normal exit, no exploit
        Err(e) if e.is::<StopSignal>() => {            // signal path
            error!(logger, "{:#}", e);                 // [2] Exploit sink #2
            0
        }
        Err(e) => {
            
            ...
            
            // [3] Exploit sink #3
            // Write attacker-influenced error to logfile ──
            // If replay() failed to parse `--time`, `e` contains that
            // controlled string and is written as root to below.log.
            error!(
                logger,
                "\n----------------- Detected unclean exit ---------------------\n\
                Error Message: {:#}\n\
                -------------------------------------------------------------",
                e
            );           
            1
        }
    }
}
```

存在三个日志记录利用点。如果我们恶意输入触发错误，它会被格式化并记录——这为我们提供了一个强大的写入原语，且具有 root 上下文。

为了验证这一点，我们将格式错误的日期字符串传入 `--time`，并观察结果：

如预期，我们的输入落入了 `/var/log/below/error_root.log`，由 root 写入。该字符串也会回显到 `stderr`。

因此，通过换行符注入，我们可以投毒系统关键文件。

> 其他子命令如 `live`、`record`、`dump` 和 `debug` 也经过其日志记录逻辑——提供了多种利用向量。

### 0x34 漏洞利用

利用 root 级任意写入权限，有几种权限提升路径可行：向 `/etc/passwd` 注入 root 用户、覆盖 `/etc/shadow`，或将 SSH 私钥放入 `/root/.ssh`。

利用的核心是一个简单的符号链接：将 `/var/log/below/error_root.log` 链接到 `/etc/passwd` 等目标。一旦 `below` 记录攻击者控制的消息，它就会以 root 权限覆盖受害者文件。

可用脚本完成利用：

我们滥用 `--time` 参数注入换行符，直接将 payload 行写入 `/etc/passwd`，将 `n0irx` 提升到 UID 0。

获取 root 权限

---

## 0xFF 总结

1. **Web 入口**：Roundcube 1.6.10 → CVE-2025-49113 → 认证后 RCE → `www-data`
2. **凭证收集**：MySQL 配置 → 会话表 → 解密 IMAP 密码 → Jacob 邮箱劫持
3. **横向移动**：邮箱密码重置邮件 → SSH 凭据 → 获取用户 shell
4. **权限提升**：Sudo `below` → CVE-2025-27591 → 符号链接日志投毒 → `/etc/passwd` 注入 → root

---

**利用链精要**：Web RCE → 数据库解密 → 邮件凭证 → SSH → Sudo 日志投毒 → 系统接管