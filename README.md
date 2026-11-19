# nginx2root_audit.sh 使用说明

> **一句话**：把这一个脚本拷到任意一台装了 nginx 的机器上，用 `sh` 跑一下，就能得到一份完整的 nginx2root 漏洞链受影响性审计报告。

---

## 1. 这个脚本检查什么

检测 2026-11-18 披露的 **nginx2root** 漏洞链：5 个可独立触发的 nginx 未认证远程代码执行漏洞（内存破坏类）。成功利用后以 nginx worker 进程权限执行任意命令；完整攻击链还需叠加一枚 Linux 内核 SCTP 提权漏洞才能取得宿主机 root（该内核漏洞**不在本脚本检测范围**）。

| CVE | QVD | 角色 | 漏洞类型 | 触发配置（必需条件） | 起始版本 |
|---|---|---|---|---|---|
| CVE-2026-123007 | QVD-2026-112201 | **主漏洞** | HTTP/2 流控发送窗口整数下溢 → 堆越界读写 | 可达 listener 启用 HTTP/2（`listen ... http2` / `http2 on`） | 1.9.5 |
| CVE-2026-123634 | QVD-2026-112241 | 子 | DNS resolver 释放后使用 (UAF) | `resolver` + 变量式/请求派生 `proxy_pass` + `mirror`/SSI 子请求 | 0.6.18 |
| CVE-2026-123633 | QVD-2026-112200 | 子 | HTTP/2 连接排空 UAF | HTTP/2 **且** 请求被转发到上游 | 1.19.7 |
| CVE-2026-121810 | QVD-2026-112308 | 子 | HTTP/3(QUIC) 连接排空 UAF | HTTP/3(QUIC) **且** 请求被转发到上游 | 1.25.0 |
| CVE-2026-113425 | QVD-2026-112251 | 子 | mail proxy `auth_http` UAF | `mail {}` 中开启 `proxy on` 且配置 `auth_http` | 0.5.33 |

**受影响版本**：上表起始版本 ~ 1.31.8
**修复版本**：nginx 开源版 `1.30.7`(stable) / `1.31.9`(mainline)；NGINX Plus `37.0.8.1` / `37.3.0.1`

> 脚本是**只读静态检测**：不发送任何攻击流量、不修改配置、不含任何利用代码，只判断「版本是否受影响 + 触发配置是否齐全」。

---

## 2. 快速开始

```bash
# 先自检脚本自身逻辑是否正确（不需要 nginx，21 项断言）
sh nginx2root_audit.sh --self-test

# 本机巡检，输出完整报告
sh nginx2root_audit.sh

# 只要结论
sh nginx2root_audit.sh --quiet

# 生成机器可读报告，便于批量收集
sh nginx2root_audit.sh --json > report.json
```

**单独下发**：脚本不依赖 PHP-FPM、不依赖本项目其他文件，只用一个 `.sh` 文件即可：

```bash
scp nginx2root_audit.sh root@target:/tmp/
ssh root@target 'sh /tmp/nginx2root_audit.sh --quiet'
```

---

## 3. 运行要求

| 项目 | 要求 |
|---|---|
| Shell | POSIX `sh`（已验证 `sh` 与 `dash`；不用 bash 数组/进程替换） |
| 依赖命令 | `grep` `sed` `awk` `find` `sort` `cut` `tr` `hostname` `uname` `date`，以及 `-o` 写报告时用到的 `tee`；均为系统基础命令 |
| nginx | 需能执行 `nginx -v`；建议以 **root** 运行以便 `nginx -T` 读取完整配置 |
| Docker | 仅 `--image` 模式需要 |
| 权限 | 只读；不需要写 nginx 配置。仅 `-o` 写报告文件时需要目标路径可写 |

脚本使用 `#!/bin/sh`，内部固定 `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`，避免从调用者环境解析到被劫持的工具。

---

## 4. 命令参数

| 参数 | 说明 |
|---|---|
| `-b, --nginx-bin PATH` | 指定 nginx 二进制。默认依次探测 `PATH` 中的 `nginx` 及常见路径（`/usr/sbin/nginx`、`/usr/local/nginx/sbin/nginx`、`/usr/local/nginxken/sbin/nginx`、`/opt/nginx/sbin/nginx`、OpenResty 等） |
| `-c, --conf-dir DIR` | 指定配置目录，用于输出「文件名:行号」证据。默认从 `nginx -V` 的 `--conf-path` 推导，再回退到常见目录 |
| `--image TAG` | 检测 nginx 容器镜像，在一次性容器内执行 `-v/-V/-T`（需 docker CLI） |
| `-o, --output FILE` | 报告同时写入文件（stdout 仍输出）。写失败仅告警，不影响漏洞判定退出码 |
| `-q, --quiet` | 只输出结论汇总 |
| `--json` | 输出结构化 JSON，自动关闭颜色与装饰 |
| `--no-color` | 关闭颜色 |
| `--self-test` | 内置自检，不访问目标 nginx |
| `-h, --help` | 显示帮助 |

颜色仅在交互式终端、未设置 `NO_COLOR`、且未使用 `--json`/`--no-color` 时自动启用；重定向到文件时自动变为纯文本。

---

## 5. 退出码（用于自动化判断）

| 码 | 含义 | 触发条件 |
|---|---|---|
| `0` | 未发现可利用面 | 无 `AFFECTED`，且无待复核/待重启/数据不完整 |
| `1` | **存在受影响路径** | 至少一项判定为 `AFFECTED` |
| `2` | 需关注 | 存在 `REVIEW`；或版本已修复但需确认 worker 已重启；或未能取得配置文本 |
| `3` | 检测无法完成 / 参数错误 | 找不到 nginx 二进制、读不到版本、docker 不可用、参数非法 |

> ⚠ `--json` 模式下退出码同样表达检测结果（脚本检测到风险时仍返回 `1`）。用 `&&` 串联命令前请先接住退出码。

CI / 批量判定示例：

```bash
sh nginx2root_audit.sh --json > report.json
rc=$?
case "$rc" in
  0) echo "PASS：未发现可利用面" ;;
  1) echo "FAIL：存在受影响路径"; exit 1 ;;
  2) echo "WARN：需人工复核（查看 report.json 的 notes / results[].verdict）" ;;
  3) echo "ERROR：检测未完成（检查 nginx 路径、root 权限）"; exit 1 ;;
esac
python3 -m json.tool report.json | head -40
```

---

## 6. 检测方法

### 6.1 三层数据源（自动降级）

| 优先级 | 数据源 | 用途 | 报告中的标注 |
|---|---|---|---|
| 1 | `nginx -T` | **运行中完整配置**（含所有 include 展开），作为主判定依据 | `数据源: nginx -T (运行中完整配置)` |
| 2 | 配置文件全文 | `-T` 不可用（通常是非 root）时回退读取 `*.conf`，去注释后判定 | `数据源: 配置文件 grep (nginx -T 不可用)` + 附加提示 |
| 辅助 | `grep -EHni` 配置文件 | 输出 `文件名:真实行号:内容` 作为**证据** | 逐项结论的「证据:」行 |
| 补充 | `nginx -V` | 编译模块（`--with-http_v2_module` 等）、`--conf-path` | `[3] 编译模块` |
| 补充 | `nginx -v` | 版本 | `[2] 版本判定` |

`--image` 模式改从一次性容器取 `-v/-V/-T`，此时配置证据来自 `-T` 输出的索引行。

### 6.2 版本判定

不使用 `sort -V`（BusyBox/老系统可能不支持），用纯 shell 逐段数字比较。按 **stable / mainline 双分支**处理，并对每个 CVE 使用独立起始版本：

| 版本 | 判定 |
|---|---|
| `< 1.9.5` | `pre-http2`：HTTP/2 类不适用，但 resolver / mail 类仍按各自起始版本判定 |
| `1.9.5 ~ 1.30.6` | 受影响（mainline 分支另有边界） |
| `1.30.7`（stable） | 已修复 |
| `1.31.0 ~ 1.31.8`（mainline） | **仍受影响** |
| `>= 1.31.9`（mainline） | 已修复 |

### 6.3 门控 + 组合条件

每个 CVE 的触发条件拆成多个子条件，逐条匹配运行中配置，输出 `n/m 命中` 与缺失项：

- `CONFIG=FULL`（全部命中）+ 版本受影响 → `AFFECTED`
- `CONFIG=PART`（部分命中）且**门控条件**命中 → `REVIEW`（需人工复核）
- 门控条件（如 HTTP/2、QUIC、resolver、mail proxy）未命中 → `NOT-EXPOSED`，避免「全局只要有 `proxy_pass` 就把 HTTP/3 漏洞误报为待复核」

### 6.4 其它检查与提示

发行版 backport（版本号可能失真）、`reload` 不替换旧二进制、`alias`+`try_files` 关联 CVE-2026-125283、`ssl_preread`、编译模块与配置不一致、版本受影响但零暴露面等，都会写入报告 `[7] 附加提示` 和 JSON `notes`。

---

## 7. 检测报告结构

文本报告共 8 个区块：

| 区块 | 内容 |
|---|---|
| `[1] 检测环境` | 主机、系统、时间、数据源、nginx 路径、配置目录 |
| `[2] 版本判定` | 原始版本串、解析版本、分支、状态、修复版本、判定方式 |
| `[3] 编译模块` | `http_v2 / http_v3 / mail / stream_ssl_preread` |
| `[4] 启用的特性` | `http2 / quic / resolver / 变量式 proxy_pass / mirror / proxy_pass / mail_proxy / ssl_preread / alias / try_files` |
| `[5] 逐项检测结果` | 对齐表格：`# / CVE / QVD / ROLE / VERSION / CONFIG / VERDICT` |
| `[6] 逐项详细结论` | 每个 CVE 的 QVD、类型、影响版本、必需配置、门控条件、条件命中数、缺失项、带行号证据、处置建议、临时缓解 |
| `[7] 附加提示` | 环境注意事项与需人工复核项 |
| `结论汇总 SUMMARY` | 计数、涉及编号、总体判定、根本修复、临时缓解、参考来源、检测局限、退出码 |

### JSON 字段

顶层：`tool / timestamp / host / os / data_source / nginx_bin / conf_dir / version_raw / version / branch / version_status / fixed_in / modules / enabled / results[] / summary / notes / remediation / limitations`

`results[]` 每项 15 个字段：`cve / qvd / role / type / affected_from / version_hit / config_status / config_hits / config_required / gate_hit / missing_conditions / evidence / verdict / advice / mitigation`

---

## 8. 结果怎么读

| 字段 | 取值 | 含义 |
|---|---|---|
| `ROLE` | `MAIN` / `SUB` | 主漏洞 / 子漏洞 |
| `VERSION` | `HIT` / `FIXED` | 版本落在受影响范围 / 已修复或不在范围 |
| `CONFIG` | `FULL` / `PART` / `NONE` | 触发条件齐全 / 部分命中 / 未启用 |
| `VERDICT` | `AFFECTED` | 版本受影响且触发条件齐全，**存在可利用面** |
| | `REVIEW` | 门控已命中但条件不齐，需人工复核 |
| | `NOT-EXPOSED` | 触发条件不齐全，当前配置下不可触发 |
| | `SAFE` | 版本已修复或不在影响范围 |

本机（`secnginx/1.30.4`）实测结论节选：

```
  │ #   │ CVE                │ QVD                │ ROLE  │ VERSION │ CONFIG  │ VERDICT      │
  │ 1   │ CVE-2026-123007    │ QVD-2026-112201    │ MAIN  │ HIT     │ FULL    │ AFFECTED     │
  │ 3   │ CVE-2026-123633    │ QVD-2026-112200    │ SUB   │ HIT     │ FULL    │ AFFECTED     │
  │ 4   │ CVE-2026-121810    │ QVD-2026-112308    │ SUB   │ HIT     │ PART    │ NOT-EXPOSED  │

   ★ 受影响   : 2   ! 待复核   : 0   - 未暴露/安全: 3
   涉及编号   : CVE-2026-123007, CVE-2026-123633
   总体判定   : 高危 - 存在可利用面, 建议立即升级
```

`CVE-2026-121810` 的 `CONFIG=PART` 是因为全局存在 `proxy_pass`，但门控条件「HTTP/3(QUIC) 已启用」未命中，因此判 `NOT-EXPOSED` 而非 `REVIEW`——这正是门控判定消除的误报。

---

## 9. 典型使用场景

**单机巡检 + 报告归档**
```bash
sh nginx2root_audit.sh -o /var/log/nginx2root-$(date +%F).txt
```

**批量下发收集**
```bash
mkdir -p reports
for h in web1 web2 web3; do
  scp -q nginx2root_audit.sh "$h":/tmp/ || continue
  ssh "$h" 'sh /tmp/nginx2root_audit.sh --json' > "reports/$h.json"
  printf '%-8s exit=%s\n' "$h" "$?"
done
python3 - <<'PY'
import json, glob
for f in sorted(glob.glob('reports/*.json')):
    d = json.load(open(f))
    print(f, d['host'], d['version'], d['version_status'], 'AFFECTED=', d['summary']['affected'])
PY
```

**中心侧检测容器镜像**（无需在目标机装 nginx）
```bash
sh nginx2root_audit.sh --image nginx:1.25 --json
```
> 镜像模式只反映镜像内默认配置；运行时挂载/覆盖的配置不会出现在 `-T` dump 中，报告会明确提示。

**非 root / `nginx -T` 不可用**
```bash
sh nginx2root_audit.sh -b /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf
```
脚本自动回退到配置文件，并在 `[7]` 与 `notes` 中标注「结论需确认是否为运行中配置」。

**下发前验证脚本自身**
```bash
sh nginx2root_audit.sh --self-test     # 通过 21 项, 失败 0 项
```

---

## 10. 修复与缓解

**根本修复**：升级到 `1.30.7`(stable) / `1.31.9`(mainline)，NGINX Plus 升至 `37.0.8.1` / `37.3.0.1`。
**必须重启 nginx 或做受支持的二进制热升级**——`nginx -s reload` 会保留旧可执行文件与旧 worker，升级不算完成。

| 临时缓解 | 能覆盖 | 不能覆盖 |
|---|---|---|
| `http2 off`（1.25.1+）或从所有 `listen` 移除 `http2` | CVE-2026-123007、CVE-2026-123633 | 123634 / 121810 / 113425 |
| 变量式 `proxy_pass` 改固定 upstream group、关闭 `mirror` | CVE-2026-123634 | 其它 |
| 移除 QUIC `listen` / `http3 off` / 阻断 UDP 443 | CVE-2026-121810 | 其它 |
| mail listener 绑定 loopback + 防火墙限制 | CVE-2026-113425 | 其它 |

注意关闭 HTTP/2 会影响 gRPC 等 HTTP/2-only 客户端；WAF 规则无法阻挡此类攻击（攻击位于 HTTP/2/3 控制帧，不是普通请求内容）。

---

## 11. 局限与注意事项

1. 只读静态评估，**不发送攻击流量**，不证明漏洞实际可被利用。
2. 配置条件为**全局匹配**，需人工确认相关指令是否处于同一 `server`/`location` 块内。
3. 发行版常 backport 补丁而不改 `X.Y.Z` 版本号，需对照发行版安全公告核对完整包版本。
4. 升级后要确认 worker 已重启，脚本对 `fixed` 版本固定给出该提示并返回退出码 `2`。
5. 镜像模式仅检测镜像内默认配置。
6. 不检测攻击链中 Linux 内核 SCTP 提权漏洞，也不检测同期修复的 CVE-2026-125283（仅在 `alias`+`try_files` 同时出现时给出复核提示）。

---

## 12. 常见问题

| 问题 | 说明 |
|---|---|
| 站点报 502，脚本还能用吗？ | 能。502 通常是 PHP-FPM 未启动，本脚本完全不依赖 PHP-FPM，只调用 nginx 二进制与读配置文件。 |
| `nginx -T` 没输出？ | 多为权限不足。脚本自动回退到配置文件并在报告中标注；建议以 root 运行以获得最准确的运行中配置。 |
| 重定向到文件后没有颜色？ | 正常，非 tty 时自动关闭；也可用 `--no-color` 或 `NO_COLOR=1`。 |
| 为什么退出码是 `2`？ | 存在待复核项、版本已修复但需确认重启、或配置数据源不完整，均归入「需关注」。 |
| `-o` 写文件失败会怎样？ | 仅打印警告，退出码仍表达漏洞判定结果。 |
| 目标机是 Alpine / BusyBox？ | 可用，脚本为 POSIX `sh`，不依赖 `sort -V`、bash 数组、`seq` 等。 |

---

## 13. 与项目内其他文件的关系

| 文件 | 定位 |
|---|---|


> 本脚本与项目内 PHP case 是两条独立路径：前者用于**下发到各系统离线巡检**，后者用于**测试站点在线验证**。

---

## 14. 参考来源

- F5 安全公告 `K000164058` / `K000163926`
- CERT-EU 安全公告 `2026-022`
- nginx.org security advisories
- Xint Security Research — NGINX2Root technical writeup（2026-11-18）
- 奇安信 CERT / 长亭 / 亚信 / 360 漏洞研究院通告、阿里云漏洞库 AVD-2026-123007
