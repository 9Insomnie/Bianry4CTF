Kerberos 对时间差异很敏感。使用包装脚本(ft.sh)在执行攻击之前调整本地时钟，使其与服务器时间一致。
```
#!/bin/bash
# Usage example: ./ft.sh $ip <command>

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <ip> <command>"
    exit 1
fi

ip="$1"
shift
command=( "$@"  )

echo "[*] Querying offset from: $ip"

# Get offset in seconds
offset_float=$(ntpdate -q "$ip" 2>/dev/null | grep -oP 'offset \+\K[0-9.]+')
if [ -z "$offset_float" ]; then
    echo "[!] Failed to extract valid offset from ntpdate."
    exit 1
fi

# Compose faketime format: +<offset>s
faketime_fmt="+${offset_float}s"

echo "[*] faketime -f format: $faketime_fmt"
echo "[*] Running: ${command[@]}"

faketime -f "$faketime_fmt" "${command[@]}"
```