#!/system/bin/sh
# KernelSU 交接脚本（payload 以 uid=0 + kernel 域执行它）。
#
# 设计要点（每一条都对应一次真机事故）：
#   1. 目标管理器包名来自 EXTRACTKIT_MGR；写死会让「选了 MilkSU 却注册成 SukiSU」。
#   2. ksud 必须来自**同一个**管理器：别的管理器的二进制拿去给本管理器注册，
#      属于跨品牌顶替，只能在没有自家 ksud 时兜底并显式告警。
#   3. ksud 只从**管理器包内**取（$APP_ROOT/*/<pkg>*/lib/arm64）。一律不从
#      /data/adb/ksu/bin/ksud 或 /data/adb/ksud 取——那是别家装过的旧件，
#      版本可能与当前管理器不符，也可能被我们自己以前写坏。
#   4. 也不再往 /data/adb 写任何东西（不覆盖 ksud、不建软链）：管理器自装的
#      那份保持原样，出问题不打我们的账。
#   5. 包内路径可能被 SELinux 挡 exec，需要可执行副本时只落到我们自己的
#      /data/local/tmp/extract-kit/bin/ksud。
#   6. EXTRACTKIT_DRYRUN=1 只做解析 + 能力探测，不动任何文件（给 App 自检用）。
#   7. EXTRACTKIT_APP_ROOT 可覆盖 /data/app，宿主机才能用假目录树测试解析。
#   8. 同一次开机里 kernelsu 已加载就不要再 late-load：包名在加载时定死。
echo "[ksu] start uid=$(id -u) selinux=$(getenforce)"
grep -E '^(Cap|Seccomp|Uid|Gid)' /proc/self/status
echo "[diag] attr=$(cat /proc/self/attr/current)"

# 9.209 取证：上次内核 panic 的正文（console-ramoops）只有 root 读得到，
# 而本脚本正是以 uid=0 + kernel 域被 exec 的，顺手把它捞到宿主机能拉的地方。
# uid!=0（shell 自检）时整段跳过，不做任何事。
if [ "$(id -u)" = "0" ]; then
  if [ -d /sys/fs/pstore ]; then
    mkdir -p /data/local/tmp/pstore 2>/dev/null
    for _f in /sys/fs/pstore/*; do
      [ -f "$_f" ] || continue
      cp -f "$_f" "/data/local/tmp/pstore/$(basename "$_f")" 2>/dev/null
    done
    chmod -R 0666 /data/local/tmp/pstore 2>/dev/null
    echo "[pstore] harvested $(ls /data/local/tmp/pstore 2>/dev/null | wc -l) file(s)"
  else
    echo "[pstore] no /sys/fs/pstore"
  fi
fi

MGR=${EXTRACTKIT_MGR:-com.sukisu.ultra}
APP_ROOT=${EXTRACTKIT_APP_ROOT:-/data/app}
DRYRUN=${EXTRACTKIT_DRYRUN:-0}
echo "[ksu] mgr=$MGR app_root=$APP_ROOT dryrun=$DRYRUN"

# 能不能读 APP_ROOT：shell 域读不了 /data/app，只有 root 能，必须报出来，
# 否则 App 自检会把"没权限"误显示成"缺 ksud"。
ROOT_OK=0
if ls "$APP_ROOT" >/dev/null 2>&1; then
  ROOT_OK=1
fi
echo "[resolve] app_root=$APP_ROOT readable=$ROOT_OK"

PROBE_DIR=/data/local/tmp/extract-kit

# 可执行候选：ELF 真二进制，或带 shebang 的脚本（全零坏文件两者都不满足）
is_bin() {
  head -c 4 "$1" 2>/dev/null | grep -qa ELF && return 0
  head -c 2 "$1" 2>/dev/null | grep -qa "#!" && return 0
  return 1
}
# 探测超时：随机 .so 里有会卡住的，别让一次 --version 把整个交接挂死
TO=""
command -v timeout >/dev/null 2>&1 && TO=timeout
run_to() { if [ -n "$TO" ]; then timeout 5 "$@"; else "$@"; fi; }

# 9.193：MapleSU 的 ksud（Rust 版）--version 首行是「KernelSU version: x」
# 里没有 ksud 这个词，只认 ksud 会把唯一候选拒掉（用户 m09750 的无效就是这里）。
# 9.194：XecPro 的 ksud（libxeccli.so）--version 打自家品牌「xudc 31431-… (uapi: 6)」，
# ksud/kernelsu 两个字都不出现（用户 m14641「latest late load 没效果」就是这里：
# 候选被 ksud_like 拒掉 → 跨包借了 Sukisu 的 ksud 去给 com.xecpro.kernel 注册）。
# 所以品牌词之外再认「(uapi: N)」，并且必须用 late-load --help 确认真是 ksud 构建，
# 否则任何顺手打了 uapi 的库都会被当成 ksud。
ksud_like() {
  _v=$(run_to "$1" --version 2>&1 | head -1)
  echo "$_v" | grep -qiE 'ksud|kernelsu' && return 0
  echo "$_v" | grep -qiE 'uapi:' || return 1
  # 9.255：老构建的 help 里可能既没有 kernelsu.ko 也没有 package-name，只认得出
  # --kmi/--allow-shell/--package-uid；这些同样证明它是 ksud 的 late-load 子命令。
  run_to "$1" late-load --help 2>&1 | grep -qiE 'kernelsu\.ko|package-name|package-uid|allow-shell|--kmi' || return 1
  return 0
}
ver_of() { run_to "$1" --version 2>&1 | head -1; }

SRC=""
SRC_OWNER=""
SRC_WHY=""

# 9.201：探测一律在 /data/local/tmp/extract-kit 里做一份副本再 exec。
# 真机上 late-load 是以 u:r:kernel:s0（root）跑的，直接 exec /data/app 里的私有 .so
# 会被 SELinux 挡（或崩在更早的初始化），表现就是「自家 ksud 探测失败 → 跨包借别人的」。
# probe_ok 通过时把副本留在 $PICK，调用方优先用它。
PICK=""
probe_ok() {
  _f=$1
  _who=$2
  if ksud_like "$_f"; then
    echo "[probe] $_who inplace=ok"
    PICK=""
    return 0
  fi
  _t=$PROBE_DIR/probe.$$
  mkdir -p "$PROBE_DIR" 2>/dev/null
  if ! cp "$_f" "$_t" 2>/dev/null; then
    echo "[probe] $_who inplace=reject copy=fail"
    return 1
  fi
  chmod 755 "$_t" 2>/dev/null
  if ksud_like "$_t"; then
    mv -f "$_t" "$PROBE_DIR/ksud.pick" 2>/dev/null && PICK="$PROBE_DIR/ksud.pick"
    echo "[probe] $_who inplace=reject copy=ok"
    return 0
  fi
  rm -f "$_t" 2>/dev/null
  echo "[probe] $_who inplace=reject copy=reject"
  return 1
}

# 静态挑自家 ksud：必须同时具备 late-load 与 package-name 两串，再用
# uapi: / "KernelSU version" / "kernelsu.ko" 打分取最高（同分取体积大的）。
# 理由：真机上这段跑在 u:r:kernel:s0，exec /data/app 里的 .so 会崩，只能靠静态特征定案；
# 但同目录下 libghostlock.so 这类也会带 late-load+kernelsu，不打分就会拿错二进制当 ksud。
static_pick() {
  _best=""; _bs=-1; _bz=0
  for _f in "$1"/*.so; do
    [ -f "$_f" ] || continue
    is_bin "$_f" || continue
    # 9.255：只要求 late-load 这一个硬特征。老构建/别家构建可能根本没有
    # package-name 串（它们用 --package-uid 或裸 late-load），以前会因为
    # 这一条把唯一正确的自家 ksud 判掉，然后整条交接 FATAL。
    grep -qa 'late-load' "$_f" 2>/dev/null || continue
    _s=0
    grep -qa 'uapi:' "$_f" 2>/dev/null && _s=$((_s+3))
    grep -qa 'KernelSU version' "$_f" 2>/dev/null && _s=$((_s+3))
    grep -qa 'kernelsu\.ko' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa 'already loaded, skip loading ko' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa 'package-name' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa 'package-uid' "$_f" 2>/dev/null && _s=$((_s+1))
    grep -qa -- '--allow-shell' "$_f" 2>/dev/null && _s=$((_s+1))
    _z=$(wc -c < "$_f" 2>/dev/null | tr -d ' ')
    [ -z "$_z" ] && _z=0
    if [ "$_s" -gt "$_bs" ] || { [ "$_s" -eq "$_bs" ] && [ "$_z" -gt "$_bz" ]; }; then
      _best=$_f; _bs=$_s; _bz=$_z
    fi
  done
  [ -n "$_best" ] && { echo "$_best"; return 0; }
  return 1
}

# 扫描一个 lib 目录，命中就填 SRC / SRC_OWNER / SRC_WHY（why=self|cross|self_static）
scan_dir() {
  [ -n "$SRC" ] && return 0
  d=$1
  [ -d "$d" ] || return 0
  # 9.201：自家目录先用静态特征定案（late-load + kernelsu 两串同时存在）。
  # 理由：真机上这一段是以 u:r:kernel:s0 跑的，同一个 .so 在这里 exec 会崩（SIGILL/segv），
  # 于是"自家没找到"→跨包借了别人的 ksud，管理器就永远注册成别家的包名。
  if [ "$3" = self ]; then
    if _p=$(static_pick "$d"); then
      SRC=$_p
      SRC_OWNER=$2
      SRC_WHY=self_static
      echo "[resolve] static pick $(basename "$_p") (best score, skip exec probe)"
      return 0
    fi
  fi
  # 两轮：先只看文件名像 ksud 的（librczajmyvun.so 这种看不出来，就落到第二轮），
  # 避免对每个随机 .so 都跑一次 --version（有的会 SIGILL，日志很脏）。
  for pass in 1 2; do
    for f in "$d"/*.so; do
      [ -f "$f" ] || continue
      case "$f" in
        *ksud*) [ "$pass" = 1 ] || continue ;;
        *)      [ "$pass" = 2 ] || continue ;;
      esac
      chmod 755 "$f" 2>/dev/null
      is_bin "$f" || continue
      probe_ok "$f" "$(basename "$f")" || continue
      SRC=${PICK:-$f}
      SRC_OWNER=$2
      SRC_WHY=$3
      return 0
    done
  done
  # 9.201：exec 探测全失败时，自家目录再用同一套静态打分兜一层。
  # rs 版 ksud 在某些内核上 exec 会立刻崩（SIGILL/segv），可它就是唯一正确的来源。
  if [ "$3" = self ]; then
    if _p=$(static_pick "$d"); then
      SRC=$_p
      SRC_OWNER=$2
      SRC_WHY=self_static
      echo "[resolve] static pick $(basename "$_p") (exec probe failed, accept by score)"
      return 0
    fi
  fi
}

# 1) 先只在目标管理器自己的 lib 里找（这才是正确来源）
for d in $(ls -d $APP_ROOT/*/"$MGR"*/lib/arm64 2>/dev/null); do
  scan_dir "$d" "$MGR" self
done

# 2) 9.204 起不再跨包借用：只在选定的这一个管理器包里找，找不到就直接失败。
#    理由：别家的 ksud 会把内核模块注册成别家的包名，管理器永远看不到 root；
#    宁可失败并明确报错，也不拿别人的二进制去顶。

# 3) 到此为止：ksud 只认选定管理器包内（self / self_static）。
#    /data/local/tmp/ksud、/data/adb/ksud、/data/adb/ksu/bin/ksud 一律不做来源 ——
#    那几个位置可能是别家装的旧版本，可能是我们自己以前写坏的，也可能是
#    本管理器不认的二进制，拿它注册等于白提权。

if [ -z "$SRC" ]; then
  if [ "$ROOT_OK" = 0 ]; then
    echo "[resolve] mgr=$MGR src= owner= cross=0 why=noperm"
    echo "[ksu] cannot read $APP_ROOT (uid=$(id -u)); run as root to locate the manager ksud"
  else
    echo "[resolve] mgr=$MGR src= owner= cross=0 why=none"
    echo "[ksu] FATAL: no usable ksud in $MGR (scanned $APP_ROOT/*/$MGR*/lib/arm64; 9.204 policy: no cross-package borrow, no /data/adb, fail fast)"
  fi
  exit 1
fi

CROSS=0
echo "[resolve] mgr=$MGR src=$SRC owner=$SRC_OWNER cross=$CROSS why=$SRC_WHY"
echo "[ksu] source version: $(ver_of "$SRC")"

# 4) 9.255：逐 flag 探测能力。不同管理器、不同版本的 ksud late-load
#    支持的参数不一样（--kmi / --allow-shell / --package-name / --package-uid
#    任意组合，甚至有只认裸 late-load 的构建）。以前只判 --package-name
#    一个 flag，碰上只有 --package-uid 的构建就会把不支持的 flag 传进去
#    → unknown option → 整条交接 FATAL。这里把 help 里出现的每一个都记下来，
#    下面的阶梯只用真正支持的那几个去拼组合。
CAP_KMI=0; CAP_AS=0; CAP_PN=0; CAP_PUID=0
FLAG_OK=0
HELP=""
if [ "$SRC_WHY" = self_static ]; then
  # exec 探测已失败（SIGILL/被 SELinux 挡），拿不到 help。能做的是直接在
  # 二进制里找那些 flag 字符串，比“假设全部支持”准得多。
  HELP="(static)"
  grep -qa -- '--kmi' "$SRC" 2>/dev/null && CAP_KMI=1
  grep -qa -- '--allow-shell' "$SRC" 2>/dev/null && CAP_AS=1
  grep -qa -- '--package-name' "$SRC" 2>/dev/null && CAP_PN=1
  grep -qa -- '--package-uid' "$SRC" 2>/dev/null && CAP_PUID=1
  echo "[ksu] static source: flags from binary kmi=$CAP_KMI allow-shell=$CAP_AS package-name=$CAP_PN package-uid=$CAP_PUID"
  if [ $((CAP_KMI + CAP_AS + CAP_PN + CAP_PUID)) -eq 0 ]; then
    CAP_KMI=1; CAP_AS=1; CAP_PN=1
    echo "[ksu] static source: no flag strings found, assume kmi+allow-shell+package-name"
  fi
else
  HELP=$("$SRC" late-load --help 2>&1)
  [ -z "$HELP" ] && HELP=$("$SRC" --help 2>&1)
  echo "$HELP" | grep -q -- '--kmi' && CAP_KMI=1
  echo "$HELP" | grep -q -- '--allow-shell' && CAP_AS=1
  echo "$HELP" | grep -q -- '--package-name' && CAP_PN=1
  echo "$HELP" | grep -q -- '--package-uid' && CAP_PUID=1
  echo "[ksu] help: $(echo "$HELP" | grep -i -m4 -E 'kmi|package|allow-shell' | tr '
' '|')"
  echo "[ksu] caps kmi=$CAP_KMI allow-shell=$CAP_AS package-name=$CAP_PN package-uid=$CAP_PUID"
  if [ $((CAP_KMI + CAP_AS + CAP_PN + CAP_PUID)) -eq 0 ]; then
    echo "[ksu] warn: --help listed no known late-load flag; ladder will start from bare late-load"
  fi
fi
[ "$CAP_PN" = 1 ] && FLAG_OK=1

# 5) 自检模式：到此为止，不碰 /data/adb
if [ "$DRYRUN" != 0 ]; then
  echo "[resolve] dryrun=1, nothing written (policy: package-local only, no /data/adb)"
  exit 0
fi

# 6) 直接从包内那份跑；/data/app 可能被 SELinux 挡 exec，就在我们自己的目录里
#    放一份可执行副本（绝不写 /data/adb）。
KSUD="$SRC"
BIN_DIR=/data/local/tmp/extract-kit/bin
if mkdir -p "$BIN_DIR" 2>/dev/null && cp "$SRC" "$BIN_DIR/ksud.new" 2>/dev/null && \
   chmod 755 "$BIN_DIR/ksud.new" 2>/dev/null && mv -f "$BIN_DIR/ksud.new" "$BIN_DIR/ksud" 2>/dev/null; then
  if is_bin "$BIN_DIR/ksud" && { [ "$SRC_WHY" = self_static ] || ksud_like "$BIN_DIR/ksud"; }; then
    KSUD="$BIN_DIR/ksud"
    echo "[ksu] copied package ksud -> $KSUD (src=$SRC)"
  else
    rm -f "$BIN_DIR/ksud" 2>/dev/null
    echo "[ksu] copy self-check failed; using in-package $SRC"
  fi
else
  rm -f "$BIN_DIR/ksud.new" 2>/dev/null
  echo "[ksu] copy to $BIN_DIR failed; using in-package $SRC"
fi
if ! is_bin "$KSUD" || { [ "$SRC_WHY" != self_static ] && ! ksud_like "$KSUD"; }; then
  echo "[ksu] $KSUD self-check failed; fall back to in-package $SRC"
  KSUD="$SRC"
fi
echo "[ksu] ksud=$KSUD ver=$(ver_of "$KSUD")"

# 7) KMI 按真实内核推断（可用 EXTRACTKIT_KMI 覆盖）
KV=$(uname -r)
KMI=android15-6.6
case "$KV" in
  5.10.*) KMI=android12-5.10 ;;
  5.15.*) KMI=android13-5.15 ;;
  6.1.*) KMI=android14-6.1 ;;
  6.6.*) KMI=android15-6.6 ;;
  6.12.*) KMI=android16-6.12 ;;
  6.17.*|6.18.*) KMI=android17-6.18 ;;
esac
if [ -n "${EXTRACTKIT_KMI:-}" ]; then
  echo "[ksu] kmi override: $KMI -> $EXTRACTKIT_KMI"
  KMI="$EXTRACTKIT_KMI"
fi

# 8) 已加载就别重复 late-load（包名在加载时定死，换管理器要重启）
if grep -q '^kernelsu ' /proc/modules; then
  echo "KSU_ALREADY"
  echo "[ksu] kernelsu already running; $MGR becomes registered only after reboot"
  echo "[ksu] hint=reboot"
  echo 1 > /sys/fs/selinux/enforce 2>/dev/null
  echo "[ksu] enforce=$(getenforce)"
  exit 0
fi


# 9) 9.269: our own module loader (ko66.ko + insmod) is retired. Every family now
#    hands the late-load to the manager's own ksud, so nothing here pushes a .ko.
#    assets/payload/honor/* was deleted with the old payload line.

echo "[ksu] kmi=$KMI kernel=$KV mgr=$MGR"
# 模块签名强制：有些机型（荣耀/部分鸿蒙底包）默认打开，late-load 会被拒；
# 先临时关掉，无论成败都还原，避免留下「模块校验已关」的状态。
SIGF=/sys/module/module/parameters/sig_enforce
SIGV=""
if [ -w "$SIGF" ]; then
  SIGV=$(cat "$SIGF" 2>/dev/null)
  if echo 0 > "$SIGF" 2>/dev/null; then
    echo "[ksu] sig_enforce=$SIGV -> 0"
  else
    SIGV=""
  fi
fi
# 一次尝试：参数里已经带好 flag；成功标准是 /proc/modules 里真的出现 kernelsu
TRY_N=0
LAST_RC=1
try_load() {
  TRY_N=$((TRY_N + 1))
  echo "[ksu] late-load try=$TRY_N flags=$*"
  "$KSUD" late-load "$@" 2>&1 | tail -n 6
  LAST_RC=${PIPESTATUS[0]:-$?}
  # busybox/ash 没有 PIPESTATUS 时退化成命令自身的退出码
  echo "[ksu] late-load try=$TRY_N rc=$LAST_RC"
  # 模块 init 有延迟：立刻 grep 往往还是空的（9.200 真机上就是这样，
  # 四条全报 rc=0 失败、结尾又打 KSU_LOADED）。这里等 0.3s，最多查 3 次。
  _i=0
  while [ $_i -lt 3 ]; do
    if grep -q '^kernelsu ' /proc/modules; then
      echo "[ksu] try=$TRY_N ok (/proc/modules shows kernelsu)"
      return 0
    fi
    _i=$((_i + 1))
    sleep 0.3
  done
  return 1
}

# ---- 安全模式：加载前临时禁用已有模块，避免某个模块把 kernelsu 堵在初始化 ----
SAFE_FLAG=/data/local/tmp/extract-kit/safe_mode
SAFE_LOG=/data/local/tmp/extract-kit/safe_restore.txt
SAFE=0
[ -f "$SAFE_FLAG" ] && SAFE=1
if [ "${EXTRACTKIT_SAFE_MODE:-0}" = 1 ]; then SAFE=1; fi
safe_restore() {
  [ -f "$SAFE_LOG" ] || return 0
  N_R=0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    rm -f "$d/disable" 2>/dev/null && N_R=$((N_R + 1))
  done < "$SAFE_LOG"
  echo "[ksu] safe_mode: restored $N_R module(s)"
  rm -f "$SAFE_LOG"
}
if [ "$SAFE" = 1 ]; then
  : > "$SAFE_LOG"
  N_D=0
  for d in /data/adb/modules/*; do
    [ -d "$d" ] || continue
    [ -f "$d/disable" ] && continue
    echo "$d" >> "$SAFE_LOG"
    touch "$d/disable" 2>/dev/null && N_D=$((N_D + 1))
  done
  echo "[ksu] safe_mode: temporarily disabled $N_D module(s) (restored on success)"
fi

MGR_UID=$(stat -c %u "/data/data/$MGR" 2>/dev/null)
PUID=${MGR_UID:-0}
echo "[ksu] manager uid=$PUID (from /data/data/$MGR)"
# 9.255 阶梯：每一层都只用 help/二进制里确认过的 flag，
# 顺序从“最具体”（能把包名固定下来的）到“最保守”（裸 late-load）。
# 成功后不再继续叠加，避免已经加载了还去重试报错。
TRY_OK=0
TRY_WIN=""
lvl() {
  [ "$TRY_OK" = 1 ] && return 0
  if try_load "$@"; then TRY_OK=1; TRY_WIN="$*"; fi
  return 0
}
if [ "$CAP_PN" = 1 ]; then
  [ "$CAP_KMI" = 1 ] && [ "$CAP_AS" = 1 ] && lvl --kmi "$KMI" --allow-shell --package-name "$MGR"
  [ "$TRY_OK" = 0 ] && [ "$CAP_AS" = 1 ] && lvl --allow-shell --package-name "$MGR"
  [ "$TRY_OK" = 0 ] && [ "$CAP_KMI" = 1 ] && lvl --kmi "$KMI" --package-name "$MGR"
  [ "$TRY_OK" = 0 ] && lvl --package-name "$MGR"
fi
if [ "$TRY_OK" = 0 ] && [ "$CAP_PUID" = 1 ]; then
  [ "$CAP_KMI" = 1 ] && [ "$CAP_AS" = 1 ] && lvl --kmi "$KMI" --allow-shell --package-uid "$PUID"
  [ "$TRY_OK" = 0 ] && [ "$CAP_AS" = 1 ] && lvl --allow-shell --package-uid "$PUID"
  [ "$TRY_OK" = 0 ] && lvl --package-uid "$PUID"
fi
if [ "$TRY_OK" = 0 ] && [ "$CAP_AS" = 1 ]; then
  [ "$CAP_KMI" = 1 ] && lvl --kmi "$KMI" --allow-shell
  [ "$TRY_OK" = 0 ] && lvl --allow-shell
fi
[ "$TRY_OK" = 0 ] && [ "$CAP_KMI" = 1 ] && lvl --kmi "$KMI"
[ "$TRY_OK" = 0 ] && lvl
echo "[ksu] late-load ladder ok=$TRY_OK winner=[$TRY_WIN] tries=$TRY_N"
RC=$LAST_RC
[ "$TRY_OK" = 1 ] && RC=0
echo "[ksu] late-load rc=$RC tries=$TRY_N"
safe_restore
if [ -n "$SIGV" ]; then
  echo "$SIGV" > "$SIGF" 2>/dev/null && echo "[ksu] sig_enforce restored=$SIGV"
fi
if [ "$RC" != 0 ]; then
  KO=$(ls /data/adb/ksu/lib/*kernelsu*.ko 2>/dev/null | head -n1)
  if [ -n "$KO" ]; then
    echo "[ksu] fallback=insmod $KO"
    insmod "$KO" 2>&1 | tail -n 3
  fi
  if ! grep -q '^kernelsu ' /proc/modules; then
    safe_restore
    echo "[ksu] FATAL: late-load failed rc=$RC (no ladder level worked; this ksud rejects every flag set we detected)"
    exit 3
  fi
  echo "[ksu] insmod ok; waiting for module ready"
fi
i=0
while [ $i -lt 50 ]; do
  grep -q '^kernelsu ' /proc/modules && break
  i=$((i+1))
  sleep 0.1
done
if grep -q '^kernelsu ' /proc/modules; then echo KSU_LOADED; else echo KSU_MISSING; fi
echo 1 > /sys/fs/selinux/enforce 2>/dev/null
echo "[ksu] enforce=$(getenforce)"

# ---- zero panic_on_oops / panic_on_warn inside this boot ----
# An Android userspace reboot SIGKILLs every userspace process. Our parked fake-cred
# page is then torn down, which can raise an Oops; the kernel ships panic_on_oops=1,
# so that Oops turns a soft reboot into a full hardware reset and root is lost.
# Zero them from the ksu domain so a soft reboot is not upgraded to a full reboot.
# The kernel restores the defaults on every real reboot, hence the check runs each time.
for _k in panic_on_oops panic_on_warn; do
  _p=/proc/sys/kernel/$_k
  _v=$(cat "$_p" 2>/dev/null)
  if [ "$_v" = "0" ]; then
    echo "[ksu] $_k=0 (already)"
    continue
  fi
  su -c "echo 0 > $_p" 2>/dev/null || echo 0 > "$_p" 2>/dev/null
  echo "[ksu] $_k=$(cat "$_p" 2>/dev/null) (was ${_v:-unreadable})"
done
