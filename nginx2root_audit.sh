#!/bin/sh
# =============================================================================
#  nginx2root_audit.sh — nginx2root 漏洞链 统一受影响性检测 / 审计报告
# -----------------------------------------------------------------------------
#  合并 nginx2root-check.sh 与 check_nginx2root.sh 的检测方法:
#    A. nginx -v / -V / -T 读取「运行中」的完整配置与编译模块 (最准确)
#    B. 配置文件 grep 输出 文件名:行号 证据
#    C. 门控条件 + 组合条件判定 (消除单条件误报)
#    D. Docker 镜像模式 (无需目标机运行 nginx)
#    E. 发行版 backport / reload 未替换二进制 / 附加风险提示
#    F. CVE ↔ QVD 全量映射 + 中文详细报告 + JSON 结构化输出
#
#  覆盖 (2026-11-18 披露, 修复 1.30.7 stable / 1.31.9 mainline):
#    CVE-2026-123007 (主) QVD-2026-112201  HTTP/2 流控整数下溢 -> 堆越界写
#    CVE-2026-123634       QVD-2026-112241  DNS resolver UAF
#    CVE-2026-123633       QVD-2026-112200  HTTP/2 上游连接 UAF
#    CVE-2026-121810       QVD-2026-112308  HTTP/3(QUIC) 上游请求 UAF
#    CVE-2026-113425       QVD-2026-112251  mail proxy auth_http UAF
#
#  特性: 单文件、零外部依赖 (仅 POSIX sh + 基础命令)、只读、不发攻击流量、
#        不依赖 PHP-FPM 或本项目其他文件, 可直接下发到各系统执行。
#
#  用法: sh nginx2root_audit.sh [选项]
#    -b, --nginx-bin PATH   指定 nginx 二进制 (默认自动探测)
#    -c, --conf-dir DIR     指定配置目录 (用于证据, 默认从 -V 的 conf-path 推导)
#        --image TAG       检测 nginx 容器镜像 (需 docker CLI)
#    -o, --output FILE      报告同时写入文件 (stdout 仍输出)
#    -q, --quiet            只输出结论汇总
#        --json             输出结构化 JSON (自动关闭颜色/装饰)
#        --no-color         关闭颜色
#        --self-test        内置自检 (不访问目标 nginx, 验证判定逻辑)
#    -h, --help             显示帮助
#
#  退出码: 0 未发现可利用面  1 存在受影响路径  2 需关注(待复核/数据不完整/待重启)
#          3 检测无法完成或参数错误
# =============================================================================

# 固定 PATH, 避免从调用者环境解析到被劫持的工具 (来自 nginx2root-check.sh)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
set -f

FIXED_STABLE="1.30.7"
FIXED_MAINLINE="1.31.9"
PROG="nginx2root_audit.sh"

NGINX_BIN_OPT=""
CONF_DIR_OPT=""
IMAGE=""
OUTFILE=""
QUIET=0
JSON_MODE=0
FORCE_NOCOLOR=0
SELF_TEST=0

usage() {
    cat <<EOF
$PROG - nginx2root 漏洞链统一检测 / 审计报告 (只读, 单文件, 可独立下发)

用法: sh $PROG [选项]
  -b, --nginx-bin PATH   nginx 二进制 (默认自动探测)
  -c, --conf-dir DIR     配置目录 (提供 文件名:行号 证据)
      --image TAG        检测 nginx 容器镜像 (需 docker)
  -o, --output FILE      报告写入文件
  -q, --quiet            只输出结论汇总
      --json             结构化 JSON 输出
      --no-color         关闭颜色
      --self-test        内置自检 (无需 nginx)
  -h, --help             显示帮助

检测范围 (5 CVE / 5 QVD):
  CVE-2026-123007 (主) QVD-2026-112201   HTTP/2 流控整数下溢
  CVE-2026-123634       QVD-2026-112241   resolver UAF
  CVE-2026-123633       QVD-2026-112200   HTTP/2 上游 UAF
  CVE-2026-121810       QVD-2026-112308   HTTP/3 上游 UAF
  CVE-2026-113425       QVD-2026-112251   mail proxy UAF

退出码: 0 安全  1 受影响  2 需关注  3 无法完成
说明: 只读静态检测, 不发送攻击流量, 不修改任何配置。
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--nginx-bin)  [ $# -ge 2 ] || { echo "缺少参数: $1" >&2; exit 3; }; NGINX_BIN_OPT="$2"; shift 2 ;;
        -c|--conf-dir)   [ $# -ge 2 ] || { echo "缺少参数: $1" >&2; exit 3; }; CONF_DIR_OPT="$2"; shift 2 ;;
        --image)         [ $# -ge 2 ] || { echo "缺少参数: $1" >&2; exit 3; }; IMAGE="$2"; shift 2 ;;
        --image=*)       IMAGE="${1#--image=}"; shift ;;
        -o|--output)     [ $# -ge 2 ] || { echo "缺少参数: $1" >&2; exit 3; }; OUTFILE="$2"; shift 2 ;;
        -q|--quiet)      QUIET=1; shift ;;
        --json)          JSON_MODE=1; FORCE_NOCOLOR=1; shift ;;
        --no-color)      FORCE_NOCOLOR=1; shift ;;
        --self-test)     SELF_TEST=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *) echo "未知参数: $1 (用 --help 查看用法)" >&2; exit 3 ;;
    esac
done

# ---------- 颜色 ----------
R=""; G=""; Y=""; C=""; B=""; DIM=""; NC=""
if [ "$FORCE_NOCOLOR" -eq 0 ] && [ "$JSON_MODE" -eq 0 ] && [ "$SELF_TEST" -eq 0 ] \
   && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
    C=$(printf '\033[36m'); B=$(printf '\033[1m'); DIM=$(printf '\033[2m')
    NC=$(printf '\033[0m')
fi
cell() { _cw=$1; _ct=$2; _cc=${3:-}; _cp=$(printf "%-${_cw}s" "$_ct"); printf '%s%s%s' "$_cc" "$_cp" "$NC"; }
yesno() { [ "$1" = 1 ] && echo "yes" || echo "no"; }
json_str() { printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

# ---------- 版本比较 (纯 shell, 不依赖 sort -V, 兼容 BusyBox/老系统) ----------
ver_ge() { # $1 >= $2
    _va=$1; _vb=$2; _vi=0
    while [ "$_vi" -lt 3 ]; do
        _vi=$(( _vi + 1 ))
        _vx=${_va%%.*}; _vy=${_vb%%.*}
        _rest=${_va#*.}; [ "$_rest" = "$_va" ] && _va=0 || _va=$_rest
        _rest=${_vb#*.}; [ "$_rest" = "$_vb" ] && _vb=0 || _vb=$_rest
        [ -z "$_vx" ] && _vx=0
        [ -z "$_vy" ] && _vy=0
        case "$_vx$_vy" in *[!0-9]*) return 1 ;; esac
        if [ "$_vx" -gt "$_vy" ]; then return 0; fi
        if [ "$_vx" -lt "$_vy" ]; then return 1; fi
    done
    return 0
}
ver_lt() { ! ver_ge "$1" "$2"; }

# 单 CVE 的版本判定: >=min 且 (stable<1.30.7 或 mainline 1.31.0~1.31.8)
version_affected() {
    _vv=$1; _vmin=$2
    ver_ge "$_vv" "$_vmin" || return 1
    if ver_lt "$_vv" "$FIXED_STABLE"; then return 0; fi
    if ver_ge "$_vv" 1.31.0 && ver_lt "$_vv" "$FIXED_MAINLINE"; then return 0; fi
    return 1
}

# ---------- 5 个 case (单引号保护, 字段内不得含 | ) ----------
# 字段: cve|qvd|role|min|vtype|need|reqs|gate|advice|mitig
CASES='CVE-2026-123007|QVD-2026-112201|MAIN|1.9.5|HTTP/2 流量控制发送窗口整数下溢 -> 越界堆读写|可达 listener 启用 HTTP/2 (listen ... http2 / http2 on)|h2|h2|升级 1.30.7/1.31.9；确认用重启而非 reload|http2 off (1.25.1+) 或从所有 listen 移除 http2
CVE-2026-123634|QVD-2026-112241|SUB|0.6.18|DNS resolver 释放后使用 (UAF)|resolver + 变量式/请求派生 proxy_pass + mirror/SSI 子请求|resolver varproxy mirror|resolver|改用固定 upstream group 替代变量式 proxy_pass；关闭 mirror|关闭 HTTP/2 无效；需改 resolver/子请求配置
CVE-2026-123633|QVD-2026-112200|SUB|1.19.7|HTTP/2 连接排空释放后使用 (UAF)|HTTP/2 且请求被转发到上游 proxy_pass/grpc_pass|h2 upstream|h2|升级 1.30.7/1.31.9|http2 off 可缓解 (gRPC 客户端会中断)
CVE-2026-121810|QVD-2026-112308|SUB|1.25.0|HTTP/3(QUIC) 连接排空释放后使用 (UAF)|HTTP/3(QUIC) 且请求被转发到上游|quic upstream|quic|升级 1.30.7/1.31.9|移除 quic listen / http3 off / 阻断 UDP 443；关闭 HTTP/2 无效
CVE-2026-113425|QVD-2026-112251|SUB|0.5.33|mail proxy auth_http 释放后使用 (UAF)|mail{} 中开启 proxy on 且配置 auth_http|mail|mail|升级 1.30.7/1.31.9|IMAP/POP3/SMTP listener 绑定 loopback 并置于防火墙后；关闭 HTTP/2 无效'

# 条件 -> 正则 / 中文标签
cond_pattern() {
    case "$1" in
        h2)        printf '%s' '^[[:space:]]*http2[[:space:]]+on|listen[^;]*[[:space:]]http2' ;;
        quic)      printf '%s' 'listen[^;]*[[:space:]]quic|^[[:space:]]*http3[[:space:]]+on' ;;
        resolver)  printf '%s' '^[[:space:]]*resolver[[:space:]]' ;;
        varproxy)  printf '%s' 'proxy_pass[[:space:]]+[^;]*\$' ;;
        mirror)    printf '%s' '^[[:space:]]*mirror[[:space:]]' ;;
        upstream)  printf '%s' '^[[:space:]]*(proxy_pass|grpc_pass)[[:space:]]' ;;
        mail)      printf '%s' 'auth_http[[:space:]]|proxy[[:space:]]+on' ;;
        *)         printf '%s' '^$' ;;
    esac
}
cond_label() {
    case "$1" in
        h2)       echo "HTTP/2 已启用" ;;
        quic)     echo "HTTP/3(QUIC) 已启用" ;;
        resolver) echo "启用 resolver" ;;
        varproxy) echo "变量式 proxy_pass" ;;
        mirror)   echo "mirror/SSI 子请求" ;;
        upstream) echo "转发到上游" ;;
        mail)     echo "mail proxy auth_http" ;;
        *)        echo "$1" ;;
    esac
}

# ---------- 全局采集结果 ----------
VER_RAW=""; VER=""; BRANCH=""; VER_STATUS="unknown"
NGINX_BIN=""; CONF_DIR=""; CONF_PATH=""; DATA_SOURCE=""; CFG_V=""; CFG_T_RAW=""
CFG_DUMP=""; CFG_EVID=""; CFG_INDEXED=""
MOD_HTTP2=0; MOD_HTTP3=0; MOD_MAIL=0; MOD_SSLPRE=0
EN_HTTP2=0; EN_HTTP3=0; EN_RESOLVER=0; EN_VARPROXY=0; EN_MIRROR=0
EN_UPSTREAM=0; EN_MAIL=0; EN_SSLPRE=0; EN_ALIAS=0; EN_TRYFILES=0
NOTES=""; HOST=""; OSNAME=""; STAMP=""
add_note() { NOTES="${NOTES:+$NOTES|}$1"; }

# 宽正则: 用于从配置文件预筛出所有相关行, 供证据复用
WIDE_RE='http2|http3|quic|resolver|proxy_pass|grpc_pass|mirror|auth_http|mail|ssl_preread|alias|try_files|proxy[[:space:]]+on'

# 证据: 优先配置文件(真实文件名:行号), 其次 nginx -T 索引行
evid() {
    _ep=$1
    if [ -n "$CFG_EVID" ]; then
        printf '%s\n' "$CFG_EVID" | grep -Ei "$_ep" | head -2
    elif [ -n "$CFG_INDEXED" ]; then
        printf '%s\n' "$CFG_INDEXED" | grep -Ei "$_ep" | head -2
    else
        echo ""
    fi
}

# 单条件命中判定: 以「运行中完整配置」为准; 设置 EVID
cond_hit() {
    _ch=$1; _cp=$(cond_pattern "$_ch")
    if printf '%s\n' "$CFG_DUMP" | grep -Eqi "$_cp"; then
        EVID=$(evid "$_cp")
        return 0
    fi
    EVID=""
    return 1
}

# 采集: 定位 nginx / 取版本 / 取 -V / 取 -T / 取配置证据
collect() {
    HOST=$(hostname 2>/dev/null || echo unknown)
    STAMP=$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)
    OSNAME=$(uname -srm 2>/dev/null || echo unknown)
    if [ -f /etc/os-release ]; then
        _pretty=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '"')
        [ -n "$_pretty" ] && OSNAME="$OSNAME ($_pretty)"
    fi

    if [ -n "$IMAGE" ]; then
        DATA_SOURCE="docker image: $IMAGE"
        command -v docker >/dev/null 2>&1 || { add_note "docker CLI 不可用, 无法检测镜像"; return 1; }
        VER_RAW=$(docker run --rm --entrypoint nginx "$IMAGE" -v 2>&1)
        CFG_V=$(docker run --rm --entrypoint nginx "$IMAGE" -V 2>&1)
        CFG_T_RAW=$(docker run --rm --entrypoint nginx "$IMAGE" -T 2>/dev/null)
        NGINX_BIN="nginx (in image $IMAGE)"
        CONF_DIR="N/A (image)"
        add_note "镜像模式仅检测镜像内默认配置; 运行时挂载或覆盖的配置不会体现在 -T dump 中"
        [ -z "$CFG_T_RAW" ] && add_note "镜像 nginx -T 未返回配置, 仅能按版本判定"
    else
        # 定位二进制
        if [ -n "$NGINX_BIN_OPT" ]; then
            NGINX_BIN="$NGINX_BIN_OPT"
        elif command -v nginx >/dev/null 2>&1; then
            NGINX_BIN=$(command -v nginx)
        else
            for _p in /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/nginxken/sbin/nginx \
                      /opt/nginx/sbin/nginx /usr/local/bin/nginx /usr/local/openresty/nginx/sbin/nginx; do
                [ -x "$_p" ] && { NGINX_BIN="$_p"; break; }
            done
        fi
        [ -z "$NGINX_BIN" ] || [ ! -x "$NGINX_BIN" ] && { add_note "未找到可执行的 nginx 二进制, 请用 --nginx-bin 指定"; return 1; }

        VER_RAW=$("$NGINX_BIN" -v 2>&1)
        CFG_V=$("$NGINX_BIN" -V 2>&1)
        CFG_T_RAW=$("$NGINX_BIN" -T 2>/dev/null)

        CONF_PATH=$(printf '%s\n' "$CFG_V" | tr ' ' '\n' | sed -n 's/^--conf-path=//p' | head -1)
        if [ -n "$CONF_DIR_OPT" ]; then
            CONF_DIR="$CONF_DIR_OPT"
        elif [ -n "$CONF_PATH" ]; then
            CONF_DIR=${CONF_PATH%/*}
        else
            for _d in /usr/local/nginx/conf /usr/local/nginxken/conf /etc/nginx /usr/local/etc/nginx; do
                [ -d "$_d" ] && { CONF_DIR="$_d"; break; }
            done
        fi

        if [ -n "$CFG_T_RAW" ]; then
            DATA_SOURCE="nginx -T (运行中完整配置)"
        else
            DATA_SOURCE="配置文件 grep (nginx -T 不可用)"
            add_note "nginx -T 未返回配置 (通常需 root); 已回退到配置文件 grep, 结论需确认是否为运行中配置"
        fi
    fi

    # 版本解析 (只取真正的 nginx version 行, 忽略警告)
    VER_RAW=$(printf '%s\n' "$VER_RAW" | grep -i 'nginx version' | head -1)
    VER=$(printf '%s' "$VER_RAW" | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p' | head -1)
    BRANCH=$(printf '%s' "$VER" | cut -d. -f1,2)

    # 编译模块
    printf '%s' "$CFG_V" | grep -q -- '--with-http_v2_module'            && MOD_HTTP2=1
    printf '%s' "$CFG_V" | grep -q -- '--with-http_v3_module'            && MOD_HTTP3=1
    printf '%s' "$CFG_V" | grep -q -- '--with-mail'                      && MOD_MAIL=1
    printf '%s' "$CFG_V" | grep -q -- '--with-stream_ssl_preread_module' && MOD_SSLPRE=1

    # ---- 配置文本 (判定用) ----
    # nginx -T 原始输出带 "# configuration file ..." 标记, 提取成 文件:行:内容 索引
    if [ -n "$CFG_T_RAW" ]; then
        CFG_INDEXED=$(printf '%s\n' "$CFG_T_RAW" | awk '
            /^# configuration file / { f=$0; sub(/^# configuration file /,"",f); sub(/:[[:space:]]*$/,"",f); next }
            { l=$0; sub(/#.*/,"",l); print (f=="" ? "nginx.conf" : f) ":" NR ":" l }')
        CFG_DUMP=$(printf '%s\n' "$CFG_T_RAW" | sed 's/#.*//')
    fi

    # ---- 配置证据 (文件名:真实行号) ----
    if [ -n "$CONF_DIR" ] && [ -d "$CONF_DIR" ]; then
        # -Hni 输出 文件:行号:内容, 供证据展示与回退判定; 不可再加路径前缀
        CFG_EVID=$(find "$CONF_DIR" -type f \( -name '*.conf' -o -name '*.conf.*' \) \
                   ! -name '*.bak*' ! -name '*~' ! -name '*.orig' 2>/dev/null | sort | while IFS= read -r _f; do
                       grep -EHni "$WIDE_RE" "$_f" 2>/dev/null
                   done | grep -vE ':[0-9]+:[[:space:]]*#')
        # -T 不可用时, 读取配置文件全文(仅去注释)作为判定文本,
        # 避免预筛证据行漏掉 proxy on / mail{} 等指令造成口径不一致
        if [ -z "$CFG_DUMP" ]; then
            CFG_DUMP=$(find "$CONF_DIR" -type f \( -name '*.conf' -o -name '*.conf.*' \) \
                       ! -name '*.bak*' ! -name '*~' ! -name '*.orig' 2>/dev/null | sort | while IFS= read -r _f; do
                           sed 's/#.*//' "$_f" 2>/dev/null
                       done)
        fi
    fi
    [ -z "$CFG_DUMP" ] && CFG_DUMP=""

    # ---- 启用的特性 (全局概览, 与逐项 cond_hit 保持同一正则口径) ----
    _on() { printf '%s\n' "$CFG_DUMP" | grep -Eqi "$(cond_pattern "$1")" && echo 1 || echo 0; }
    EN_HTTP2=$(_on h2); EN_HTTP3=$(_on quic); EN_RESOLVER=$(_on resolver)
    EN_VARPROXY=$(_on varproxy); EN_MIRROR=$(_on mirror); EN_UPSTREAM=$(_on upstream)
    EN_MAIL=$(_on mail)
    printf '%s\n' "$CFG_DUMP" | grep -Eq 'ssl_preread[[:space:]]+on'          && EN_SSLPRE=1
    printf '%s\n' "$CFG_DUMP" | grep -Eq '^[[:space:]]*alias[[:space:]]'      && EN_ALIAS=1
    printf '%s\n' "$CFG_DUMP" | grep -Eq '^[[:space:]]*try_files[[:space:]]'  && EN_TRYFILES=1

    # ---- 整体版本状态 ----
    if [ -n "$VER" ]; then
        case "$BRANCH" in
            1.30) if ver_ge "$VER" "$FIXED_STABLE";   then VER_STATUS="fixed"; else VER_STATUS="vulnerable"; fi ;;
            1.31) if ver_ge "$VER" "$FIXED_MAINLINE"; then VER_STATUS="fixed"; else VER_STATUS="vulnerable"; fi ;;
            *)  if ver_ge "$VER" "$FIXED_MAINLINE"; then VER_STATUS="fixed"
                elif ver_ge "$VER" 1.9.5;           then VER_STATUS="vulnerable"
                else                                    VER_STATUS="pre-http2"; fi ;;
        esac
    else
        VER_STATUS="unknown"
    fi

    # ---- 附加提示 ----
    case "$VER_RAW" in
        *ubuntu*|*Ubuntu*|*debian*|*Debian*|*deb[0-9]*|*el[0-9]*|*amzn*|*alpine*|*+*|*~*)
            add_note "发行版打包版本: 版本号 X.Y.Z 可能未反映 backport 补丁, 请对照发行版安全公告核对完整包版本" ;;
    esac
    [ "$VER_STATUS" = "fixed" ] && add_note "版本已修复, 但必须重启 nginx (或受支持的二进制热升级); reload 会保留旧可执行文件与旧 worker"
    [ "$VER_STATUS" = "pre-http2" ] && add_note "版本低于 1.9.5: HTTP/2 类漏洞不适用, 但 resolver/mail 类漏洞仍需按配置判定"
    [ "$EN_ALIAS" = 1 ] && [ "$EN_TRYFILES" = 1 ] && \
        add_note "alias 与 try_files 同时出现: 请一并复核同期修复的 CVE-2026-125283"
    [ "$EN_SSLPRE" = 1 ] && add_note "启用了 ssl_preread (stream_ssl_preread): 建议一并核对 F5 公告中的 stream 相关条目"
    [ "$MOD_HTTP2" = 0 ] && [ "$EN_HTTP2" = 1 ] && \
        add_note "配置中出现 http2 指令但 -V 未见 --with-http_v2_module, 请确认该配置是否真实生效"
    [ -z "$CFG_DUMP" ] && add_note "未能取得任何配置文本, 配置暴露面结论不完整"
    return 0
}

# ---------- 单 CVE 结果计算 (设置全局 CV_* 变量) ----------
compute_result() {
    _cr_min=$1; _cr_reqs=$2; _cr_gate=$3
    CV_VSTAT="FIXED"
    [ -n "$VER" ] && version_affected "$VER" "$_cr_min" && CV_VSTAT="HIT"

    CV_NTOTAL=0; CV_NHIT=0; CV_MISS=""; CV_EVID=""; CV_HITS=""
    for _c in $_cr_reqs; do
        CV_NTOTAL=$(( CV_NTOTAL + 1 ))
        EVID=""
        if cond_hit "$_c"; then
            CV_NHIT=$(( CV_NHIT + 1 ))
            CV_HITS="$CV_HITS $_c "
            [ -n "$EVID" ] && CV_EVID="${CV_EVID}${EVID}
"
        else
            CV_MISS="${CV_MISS:+$CV_MISS, }$(cond_label "$_c")"
        fi
    done

    CV_GATEHIT=0
    case "$CV_HITS" in *" $_cr_gate "*) CV_GATEHIT=1 ;; esac
    if   [ "$CV_NHIT" -eq "$CV_NTOTAL" ]; then CV_CFGSTAT="FULL"
    elif [ "$CV_NHIT" -gt 0 ];           then CV_CFGSTAT="PART"
    else                                    CV_CFGSTAT="NONE"
    fi

    if   [ "$CV_VSTAT" = "FIXED" ]; then
        CV_VERDICT="SAFE"
    elif [ "$CV_CFGSTAT" = "FULL" ]; then
        CV_VERDICT="AFFECTED"
    elif [ "$CV_CFGSTAT" = "PART" ] && [ "$CV_GATEHIT" -eq 1 ]; then
        CV_VERDICT="REVIEW"
    else
        CV_VERDICT="NOT-EXPOSED"
    fi
}

# 遍历所有 case: $1 = table | detail | json | count
for_each_case() {
    _fm=$1; _idx=0
    [ "$_fm" = "table" ] && { echo "$T_TOP"; echo "$T_HEAD"; echo "$T_MID"; }
    [ "$_fm" = "json" ]  && printf '"results":['
    while IFS='|' read -r _cve _qvd _role _min _vtype _need _reqs _gate _advice _mitig; do
        [ -z "$_cve" ] && continue
        _idx=$(( _idx + 1 ))
        compute_result "$_min" "$_reqs" "$_gate"
        case "$_fm" in
        table)
            case "$CV_VSTAT"   in HIT) _vc="$Y" ;; *) _vc="$G" ;; esac
            case "$CV_CFGSTAT" in FULL) _cc="$R" ;; PART) _cc="$Y" ;; *) _cc="$G" ;; esac
            case "$CV_VERDICT" in AFFECTED) _dc="$R" ;; REVIEW) _dc="$Y" ;; *) _dc="$G" ;; esac
            printf "  │ %-3s │ %-18s │ %-18s │ %-5s │ %s │ %s │ %s │\n" \
                "$_idx" "$_cve" "$_qvd" "$_role" \
                "$(cell 7 "$CV_VSTAT" "$_vc")" "$(cell 7 "$CV_CFGSTAT" "$_cc")" \
                "$(cell 12 "$CV_VERDICT" "$_dc")"
            ;;
        detail)
            case "$CV_VERDICT" in
                AFFECTED)    _tag="${R}★ 受影响 / 触发条件齐全${NC}" ;;
                REVIEW)      _tag="${Y}! 待复核 / 部分条件命中${NC}" ;;
                NOT-EXPOSED) _tag="${G}- 未暴露 / 触发条件不齐全${NC}" ;;
                *)           _tag="${G}- 安全 / 版本已修复或不在范围${NC}" ;;
            esac
            printf "  %s%s%s  [%s]  %s\n" "$B" "$_cve" "$NC" "$_role" "$_tag"
            printf "     QVD 编号   : %s\n" "$_qvd"
            printf "     漏洞类型   : %s\n" "$_vtype"
            printf "     影响版本   : %s ~ 1.31.8   修复: %s / %s\n" "$_min" "$FIXED_STABLE" "$FIXED_MAINLINE"
            printf "     必需配置   : %s\n" "$_need"
            printf "     门控条件   : %s  %s\n" "$(cond_label "$_gate")" \
                "$([ "$CV_GATEHIT" = 1 ] && printf '%s[已命中]%s' "$Y" "$NC" || printf '%s[未命中 -> 不可触发]%s' "$G" "$NC")"
            printf "     条件检查   : %d/%d 命中%s\n" "$CV_NHIT" "$CV_NTOTAL" \
                "$([ -n "$CV_MISS" ] && printf '  (缺: %s)' "$CV_MISS")"
            if [ -n "$CV_EVID" ]; then
                printf '%s' "$CV_EVID" | grep -v '^$' | head -2 | while IFS= read -r _ev; do
                    printf "     ${DIM}证据: %s${NC}\n" "$(printf '%s' "$_ev" | cut -c1-160)"
                done
            fi
            printf "     处置建议   : %s\n" "$_advice"
            printf "     临时缓解   : %s\n\n" "$_mitig"
            ;;
        json)
            [ "$_idx" -gt 1 ] && printf ','
            printf '{"cve":%s,"qvd":%s,"role":%s,"type":%s,"affected_from":%s,"version_hit":%s,"config_status":%s,"config_hits":%d,"config_required":%d,"gate_hit":%s,"missing_conditions":%s,"evidence":%s,"verdict":%s,"advice":%s,"mitigation":%s}' \
                "$(json_str "$_cve")" "$(json_str "$_qvd")" "$(json_str "$_role")" "$(json_str "$_vtype")" \
                "$(json_str "$_min")" "$([ "$CV_VSTAT" = HIT ] && echo true || echo false)" \
                "$(json_str "$CV_CFGSTAT")" "$CV_NHIT" "$CV_NTOTAL" \
                "$([ "$CV_GATEHIT" = 1 ] && echo true || echo false)" \
                "$(json_str "$CV_MISS")" "$(json_str "$(printf '%s' "$CV_EVID" | tr '\n' ' ')")" \
                "$(json_str "$CV_VERDICT")" "$(json_str "$_advice")" "$(json_str "$_mitig")"
            ;;
        count)
            case "$CV_VERDICT" in
                AFFECTED) N_AFFECTED=$(( N_AFFECTED + 1 )); RISK_LIST="${RISK_LIST:+$RISK_LIST, }$_cve" ;;
                REVIEW)   N_REVIEW=$(( N_REVIEW + 1 ));   RISK_LIST="${RISK_LIST:+$RISK_LIST, }$_cve" ;;
                SAFE)     N_SAFE=$(( N_SAFE + 1 )) ;;
                *)        N_NOEXPOSED=$(( N_NOEXPOSED + 1 )) ;;
            esac
            ;;
        esac
    done <<EOF_CASES
$CASES
EOF_CASES
    [ "$_fm" = "table" ] && echo "$T_BOT"
    [ "$_fm" = "json" ]  && printf ']'
}

# ---------- 内置自检 (不访问目标 nginx) ----------
ST_PASS=0; ST_FAIL=0
st_assert() { # 实际值 期望值 描述
    if [ "$1" = "$2" ]; then ST_PASS=$(( ST_PASS + 1 ));
    else printf '  FAIL: %s (期望 %s, 实际 %s)\n' "$3" "$2" "$1"; ST_FAIL=$(( ST_FAIL + 1 )); fi
}
self_test() {
    ST_PASS=0; ST_FAIL=0
    echo "nginx2root_audit.sh 内置自检 (仅验证判定逻辑, 不访问目标 nginx)"
    echo "------------------------------------------------------------"
    ver_ge 1.30.7 1.30.6; st_assert $? 0 "ver_ge 1.30.7>=1.30.6"
    ver_ge 1.31.9 1.31.9; st_assert $? 0 "ver_ge 1.31.9>=1.31.9"
    ver_lt 1.31.8 1.31.9; st_assert $? 0 "ver_lt 1.31.8<1.31.9"
    ver_lt 1.9.4 1.9.5;   st_assert $? 0 "ver_lt 1.9.4<1.9.5"
    ver_ge 1.9.5 1.9.5;   st_assert $? 0 "ver_ge 1.9.5>=1.9.5"
    # 双分支边界 (0=版本受影响, 1=不受影响)
    version_affected 1.30.4 1.9.5; st_assert $? 0 "1.30.4 受影响"
    version_affected 1.30.7 1.9.5; st_assert $? 1 "1.30.7 stable 已修复"
    version_affected 1.31.8 1.9.5; st_assert $? 0 "1.31.8 mainline 仍受影响"
    version_affected 1.31.9 1.9.5; st_assert $? 1 "1.31.9 mainline 已修复"
    version_affected 1.9.4  1.9.5; st_assert $? 1 "1.9.4 低于起始版本"
    version_affected 1.19.6 1.19.7; st_assert $? 1 "1.19.6 未达 123633 起始版本"
    # 配置正则 (内置样例, 模拟运行中完整配置)
    CFG_DUMP='http {
        http2 on;
        listen 443 quic reuseport;
        resolver 8.8.8.8;
        proxy_pass http://$backend;
        mirror /mirror;
        grpc_pass grpc://up;
    }
    mail { proxy on; auth_http 127.0.0.1/auth; }'
    CFG_EVID=""; CFG_INDEXED=""
    cond_hit h2;       st_assert $? 0 "正则命中 h2"
    cond_hit quic;     st_assert $? 0 "正则命中 quic"
    cond_hit resolver; st_assert $? 0 "正则命中 resolver"
    cond_hit varproxy; st_assert $? 0 "正则命中 变量式 proxy_pass"
    cond_hit mirror;   st_assert $? 0 "正则命中 mirror"
    cond_hit upstream; st_assert $? 0 "正则命中 upstream"
    cond_hit mail;     st_assert $? 0 "正则命中 mail proxy"
    # 门控 / 判定: 需先给出模拟版本, 否则 compute_result 会走版本安全分支
    # 注意: 配置正则带 ^ 行首锚定, 样例须按真实 nginx 格式每条指令独占一行
    VER=1.30.4
    CFG_DUMP='http {
    proxy_pass http://backend;
}'
    compute_result 1.25.0 "quic upstream" "quic"
    st_assert "$CV_VERDICT" "NOT-EXPOSED" "门控未命中应判 NOT-EXPOSED"
    CFG_DUMP='http {
    listen 443 quic;
    proxy_pass http://backend;
}'
    compute_result 1.25.0 "quic upstream" "quic"
    st_assert "$CV_VERDICT" "AFFECTED" "条件齐全应判 AFFECTED"
    VER=1.31.9
    compute_result 1.25.0 "quic upstream" "quic"
    st_assert "$CV_VERDICT" "SAFE" "已修复版本应判 SAFE"
    echo "------------------------------------------------------------"
    echo "通过 $ST_PASS 项, 失败 $ST_FAIL 项"
    [ "$ST_FAIL" -eq 0 ] || return 1
    return 0
}
[ "$SELF_TEST" -eq 1 ] && { self_test; exit $?; }

# ---------- 主流程 ----------
collect
COLLECT_RC=$?
if [ "$COLLECT_RC" -ne 0 ] || [ -z "$VER" ]; then
    if [ "$JSON_MODE" -eq 1 ]; then
        printf '{"tool":%s,"error":"cannot collect nginx version/config","notes":[' "$(json_str "$PROG")"
        _f=1; _oifs=$IFS; IFS='|'
        for _n in $NOTES; do [ "$_f" = 1 ] || printf ','; json_str "$_n"; _f=0; done
        IFS=$_oifs
        printf '],"exit_code":3}\n'
    else
        echo "${R}[x] 检测无法完成${NC}: 未取得 nginx 版本/配置"
        _oifs=$IFS; IFS='|'; for _n in $NOTES; do echo "  - $_n"; done; IFS=$_oifs
        echo "  请用 --nginx-bin 指定二进制, 或以 root 运行以便 nginx -T 读取完整配置。"
    fi
    exit 3
fi

N_AFFECTED=0; N_REVIEW=0; N_NOEXPOSED=0; N_SAFE=0; RISK_LIST=""
for_each_case count
[ -z "$RISK_LIST" ] && RISK_LIST="无"
if [ "$VER_STATUS" = "vulnerable" ] && [ "$N_AFFECTED" -eq 0 ] && [ "$N_REVIEW" -eq 0 ]; then
    add_note "版本受影响但未见触发配置: 仍建议升级, 并确认所读配置即为当前运行中的配置"
fi

# 退出码: 1 受影响 / 2 需关注 / 0 安全
EXIT_CODE=0
if [ "$N_AFFECTED" -gt 0 ]; then
    EXIT_CODE=1
elif [ "$N_REVIEW" -gt 0 ] || [ "$VER_STATUS" = "fixed" ] || [ -z "$CFG_DUMP" ]; then
    EXIT_CODE=2
fi

T_TOP="  ┌─────┬────────────────────┬────────────────────┬───────┬─────────┬─────────┬──────────────┐"
T_MID="  ├─────┼────────────────────┼────────────────────┼───────┼─────────┼─────────┼──────────────┤"
T_BOT="  └─────┴────────────────────┴────────────────────┴───────┴─────────┴─────────┴──────────────┘"
T_HEAD=$(printf "  │ %-3s │ %-18s │ %-18s │ %-5s │ %s │ %s │ %s │\n" \
    "#" "CVE" "QVD" "ROLE" "$(cell 7 VERSION "$B")" "$(cell 7 CONFIG "$B")" "$(cell 12 VERDICT "$B")")

SEP="  ══════════════════════════════════════════════════════════════════════════════════════════"
SUB="  ──────────────────────────────────────────────────────────────────────────────────────────"

emit_json() {
    printf '{'
    printf '"tool":%s,"timestamp":%s,"host":%s,"os":%s,' \
        "$(json_str "$PROG")" "$(json_str "$STAMP")" "$(json_str "$HOST")" "$(json_str "$OSNAME")"
    printf '"data_source":%s,"nginx_bin":%s,"conf_dir":%s,"version_raw":%s,"version":%s,"branch":%s,"version_status":%s,"fixed_in":{"stable":%s,"mainline":%s},' \
        "$(json_str "$DATA_SOURCE")" "$(json_str "$NGINX_BIN")" "$(json_str "$CONF_DIR")" \
        "$(json_str "$VER_RAW")" "$(json_str "$VER")" "$(json_str "$BRANCH")" "$(json_str "$VER_STATUS")" \
        "$(json_str "$FIXED_STABLE")" "$(json_str "$FIXED_MAINLINE")"
    printf '"modules":{"http2":%s,"http3":%s,"mail":%s,"stream_ssl_preread":%s},' \
        "$(yesno $MOD_HTTP2 | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $MOD_HTTP3 | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $MOD_MAIL  | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $MOD_SSLPRE | sed 's/yes/true/;s/no/false/')"
    printf '"enabled":{"http2":%s,"http3_quic":%s,"resolver":%s,"variable_proxy_pass":%s,"mirror":%s,"proxy_pass":%s,"mail_proxy":%s,"ssl_preread":%s,"alias":%s,"try_files":%s},' \
        "$(yesno $EN_HTTP2 | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_HTTP3 | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_RESOLVER | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_VARPROXY | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_MIRROR | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_UPSTREAM | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_MAIL | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_SSLPRE | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_ALIAS | sed 's/yes/true/;s/no/false/')" \
        "$(yesno $EN_TRYFILES | sed 's/yes/true/;s/no/false/')"
    for_each_case json
    printf ',"summary":{"total":5,"affected":%d,"review":%d,"not_exposed":%d,"safe":%d,"risk_cves":%s,"exit_code":%d},' \
        "$N_AFFECTED" "$N_REVIEW" "$N_NOEXPOSED" "$N_SAFE" "$(json_str "$RISK_LIST")" "$EXIT_CODE"
    printf '"notes":['
    _jf=1; _jifs=$IFS; IFS='|'
    for _jn in $NOTES; do [ "$_jf" = 1 ] || printf ','; json_str "$_jn"; _jf=0; done
    IFS=$_jifs
    printf '],"remediation":{"upgrade":"1.30.7 stable / 1.31.9 mainline, restart required (reload keeps old binary)","mitigation":"http2 off only covers CVE-2026-123007 and CVE-2026-123633","references":["F5 K000164058 / K000163926","CERT-EU 2026-022","nginx.org security advisories","Xint NGINX2Root writeup"]},"limitations":["read-only static assessment, no attack traffic sent","config conditions matched globally; confirm same server/location block","distro backports may make X.Y.Z misleading","WAF rules cannot block HTTP/2 control-frame attacks"]'
    printf '}\n'
}

emit_summary() {
    echo "  ${B}结论汇总  SUMMARY${NC}"
    echo "$SEP"
    printf "   扫描范围   : 5 个 CVE / 5 个 QVD (nginx2root 漏洞链, 主漏洞 CVE-2026-123007)\n"
    printf "   nginx 版本 : %s [%s]   修复版本: %s / %s\n" "$VER" "$VER_STATUS" "$FIXED_STABLE" "$FIXED_MAINLINE"
    printf "   ${R}★ 受影响   : %d${NC}   ${Y}! 待复核   : %d${NC}   ${G}- 未暴露/安全: %d${NC}\n" \
        "$N_AFFECTED" "$N_REVIEW" "$(( N_NOEXPOSED + N_SAFE ))"
    printf "   涉及编号   : %s\n" "$RISK_LIST"
    if [ "$N_AFFECTED" -gt 0 ]; then
        printf "   总体判定   : ${R}${B}高危 - 存在可利用面, 建议立即升级${NC}\n"
    elif [ "$N_REVIEW" -gt 0 ]; then
        printf "   总体判定   : ${Y}${B}需人工复核 - 部分触发条件已具备${NC}\n"
    elif [ "$VER_STATUS" = "fixed" ]; then
        printf "   总体判定   : ${G}${B}版本已修复, 请确认 worker 已重启${NC}\n"
    else
        printf "   总体判定   : ${G}${B}未发现可利用面${NC}\n"
    fi
}

emit_report() {
    if [ "$JSON_MODE" -eq 1 ]; then emit_json; return; fi
    if [ "$QUIET" -eq 1 ]; then emit_summary; echo; return; fi

    _box=""; _bi=0
    while [ "$_bi" -lt 86 ]; do _box="$_box─"; _bi=$(( _bi + 1 )); done
    echo
    printf "  %s%s┌%s┐%s\n" "$B" "$C" "$_box" "$NC"
    printf "  %s%s│ %-84s │%s\n" "$B" "$C" "NGINX2ROOT  SECURITY  AUDIT  -  5 CVEs / 5 QVDs / 2026-11-18" "$NC"
    printf "  %s%s└%s┘%s\n" "$B" "$C" "$_box" "$NC"
    echo "     nginx2root nginx 多个远程代码执行漏洞 · 统一受影响性检测 (只读, 不发攻击流量)"

    echo; echo "  ${B}[1] 检测环境${NC}"
    echo "$SUB"
    printf "   主机 / 系统 : %s / %s\n" "$HOST" "$OSNAME"
    printf "   检测时间   : %s\n" "$STAMP"
    printf "   数据源     : %s\n" "$DATA_SOURCE"
    printf "   nginx 路径 : %s\n" "$NGINX_BIN"
    printf "   配置目录   : %s\n" "$CONF_DIR"

    echo; echo "  ${B}[2] 版本判定${NC}"
    echo "$SUB"
    printf "   原始版本串 : %s\n" "$VER_RAW"
    printf "   解析版本   : %s   分支 %s   状态 %s\n" "$VER" "$BRANCH" "$VER_STATUS"
    printf "   修复版本   : %s (stable) / %s (mainline)\n" "$FIXED_STABLE" "$FIXED_MAINLINE"
    printf "   判定方式   : 每个 CVE 独立起始版本 + stable/mainline 双分支修复边界\n"

    echo; echo "  ${B}[3] 编译模块 (nginx -V)${NC}"
    echo "$SUB"
    printf "   http_v2=%s  http_v3=%s  mail=%s  stream_ssl_preread=%s\n" \
        "$(yesno $MOD_HTTP2)" "$(yesno $MOD_HTTP3)" "$(yesno $MOD_MAIL)" "$(yesno $MOD_SSLPRE)"

    echo; echo "  ${B}[4] 启用的特性 (运行中配置)${NC}"
    echo "$SUB"
    printf "   http2=%s  http3/quic=%s  resolver=%s  变量式proxy_pass=%s  mirror=%s\n" \
        "$(yesno $EN_HTTP2)" "$(yesno $EN_HTTP3)" "$(yesno $EN_RESOLVER)" "$(yesno $EN_VARPROXY)" "$(yesno $EN_MIRROR)"
    printf "   proxy_pass=%s  mail_proxy=%s  ssl_preread=%s  alias=%s  try_files=%s\n" \
        "$(yesno $EN_UPSTREAM)" "$(yesno $EN_MAIL)" "$(yesno $EN_SSLPRE)" "$(yesno $EN_ALIAS)" "$(yesno $EN_TRYFILES)"

    echo; echo "  ${B}[5] 逐项检测结果${NC}"
    for_each_case table
    echo "  ${DIM}ROLE: MAIN=主漏洞 / SUB=子漏洞   VERSION: HIT=版本受影响 FIXED=已修复/不在范围${NC}"
    echo "  ${DIM}CONFIG: FULL=条件齐全 PART=部分命中 NONE=未启用${NC}"
    echo "  ${DIM}VERDICT: ${R}AFFECTED=触发条件齐全${NC}${DIM} / ${Y}REVIEW=需人工复核${NC}${DIM} / ${G}NOT-EXPOSED=配置未暴露 SAFE=版本安全${NC}"

    echo; echo "  ${B}[6] 逐项详细结论${NC}"
    echo "$SUB"
    for_each_case detail

    echo "  ${B}[7] 附加提示 / 环境注意事项${NC}"
    echo "$SUB"
    if [ -n "$NOTES" ]; then
        _nifs=$IFS; IFS='|'; _ni=0
        for _n in $NOTES; do _ni=$(( _ni + 1 )); printf "   %d) %s\n" "$_ni" "$_n"; done
        IFS=$_nifs
    else
        echo "   无"
    fi

    echo; emit_summary
    echo "$SUB"
    echo "   根本修复   : 升级 nginx ${FIXED_STABLE}(stable) / ${FIXED_MAINLINE}(mainline); NGINX Plus 37.0.8.1 / 37.3.0.1"
    echo "                必须重启或二进制热升级, reload 会保留旧可执行文件与旧 worker"
    echo "   临时缓解   : http2 off 仅覆盖 CVE-2026-123007 / 123633; 对 123634 / 121810 / 113425 无效"
    echo "                123634 改固定 upstream / 关 mirror; 121810 移除 quic listen、阻断 UDP 443; 113425 邮件端口绑 loopback"
    echo "   参考来源   : F5 K000164058 / K000163926 · CERT-EU 2026-022 · nginx.org security advisories"
    echo "                Xint NGINX2Root technical writeup (2026-11-18)"
    echo "$SUB"
    echo "   检测局限   : 1) 只读静态评估, 不发送攻击流量, 不证明实际可利用性"
    echo "                2) 配置条件为全局匹配, 需人工确认是否处于同一 server/location 块"
    echo "                3) 发行版 backport 可能使 X.Y.Z 版本号失真, 请对照发行版公告"
    echo "                4) 攻击位于 HTTP/2/3 控制帧, WAF 规则无法阻断"
    echo "   退出码     : $EXIT_CODE  (0 安全 / 1 受影响 / 2 需关注 / 3 无法完成)"
    echo "$SEP"
    echo
}

if [ -n "$OUTFILE" ]; then
    # 写文件失败只告警, 不覆盖漏洞判定的退出码
    emit_report | tee "$OUTFILE" || echo "警告: 报告写入 $OUTFILE 失败" >&2
else
    emit_report
fi
exit "$EXIT_CODE"
