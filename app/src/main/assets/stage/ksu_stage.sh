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

# 9.317：本脚本运行在「payload 已经把 selinux 弄成 Permissive」的窗口里，所有
# 提前失败的分支都必须先把自己造成的全局状态还原，再退出——否则一次失败就把
# 手机留在 Permissive，用户看到的是「装完什么都不对，只能重启」。
leave() {
  _e=$(cat /sys/fs/selinux/enforce 2>/dev/null)
  if [ "$_e" = "0" ]; then
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null
    echo "[ksu] selinux restored: enforce=$_e -> $(cat /sys/fs/selinux/enforce 2>/dev/null)"
  fi
  exit "$1"
}


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
# 9.289：payload 已经把 kernelsu.ko 装进内核，但管理器 appid 用的是它自己认的包名，
# 所以 MapleSu/XEC 显示未安装。REGISTER_ONLY=1 表示"不要再 insmod，只把 appid 改成本管理器"。
REGISTER_ONLY=${EXTRACTKIT_REGISTER_ONLY:-0}
MGR_UID_ENV=${EXTRACTKIT_MGR_UID:-}
# 9.291：只做发现 + CLI 自检（不打模块、不注册），给 App 一个"这台机器上这个管理器到底行不行"的探针
PROBE_ONLY=${EXTRACTKIT_PROBE_ONLY:-0}
echo "[ksu] mgr=$MGR app_root=$APP_ROOT dryrun=$DRYRUN register_only=$REGISTER_ONLY probe_only=$PROBE_ONLY mgr_uid=${MGR_UID_ENV:-?}"

# 能不能读 APP_ROOT：shell 域读不了 /data/app，只有 root 能，必须报出来，
# 否则 App 自检会把"没权限"误显示成"缺 ksud"。
ROOT_OK=0
if ls "$APP_ROOT" >/dev/null 2>&1; then
  ROOT_OK=1
fi
echo "[resolve] app_root=$APP_ROOT readable=$ROOT_OK"

PROBE_DIR=/data/local/tmp/extract-kit

# 9.292：谁在跑这个脚本。payload 的 root 子进程（PPG_ROOT_CMD 执行口）是 uid=0，
# 从 UserService 直接拉起来是 uid=2000 —— 日志里必须一眼看出来。
PPG_STATE=""
[ -n "${PPG_ROOT_CMD:-}" ] && PPG_STATE="set"
echo "[ksu] invoked-as uid=$(id -u) argv0=$0 ppg=$PPG_STATE"
# uid=0 时给 App 留两份证据（App 自己是 shell 域，读不了 /sys/module/*/parameters）：
#   root_uid    —— 证明"确实以 uid=0 跑过一次"
#   ksu_params  —— 内核参数回读（唯一不靠我们自证的 appid 判据）
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$PROBE_DIR" 2>/dev/null
  echo 0 > "$PROBE_DIR/root_uid" 2>/dev/null && chmod 0666 "$PROBE_DIR/root_uid" 2>/dev/null
  {
    for _p in /sys/module/kernelsu/parameters/* /sys/module/ksu/parameters/*; do
      [ -f "$_p" ] && echo "$(basename "$_p")=$(cat "$_p" 2>&1)"
    done
  } > "$PROBE_DIR/ksu_params" 2>/dev/null
  chmod 0666 "$PROBE_DIR/ksu_params" 2>/dev/null
  echo "[ksu] root-only dump: root_uid=$(cat "$PROBE_DIR/root_uid" 2>/dev/null) params=$(wc -l < "$PROBE_DIR/ksu_params" 2>/dev/null) line(s)"
fi

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
# 9.292：late-load 本身可能阻塞（等 init/等模块），给个上限，别让整条收尾挂死
# 9.306：单个 late-load 在真机上通常 1-2 s 就返回，30 s 只是把「挂死」拖长成
#       半分钟；用户要求整条收尾 10 s 内可见结果，这里按 4 s 截断。
RUNTO=""
command -v timeout >/dev/null 2>&1 && RUNTO="timeout 4"

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
  # --kmi/--allow-shell/--package-name；这些同样证明它是 ksud 的 late-load 子命令。
  run_to "$1" late-load --help 2>&1 | grep -qiE 'kernelsu\.ko|package-name|package-uid|allow-shell|--kmi' || return 1
  return 0
}
ver_of() { run_to "$1" --version 2>&1 | head -1; }

# ---- 9.313：资产探针。一次真机就把「这家管理器到底带不带 kernelsu.ko、CLI 认哪套
# ---- late-load 参数」问清楚，不再靠猜。全部只读，不加载任何东西。
probe_assets() {
  echo "---- probe: manager package assets ----"
  _hit=0
  for _d in "$APP_ROOT"/*/"$MGR"*/; do
    [ -d "$_d" ] || continue
    _hit=1
    echo "[probe] dir=$_d"
    ls -l "$_d/lib/arm64" 2>&1 | sed "s/^/[probe] lib: /"
    ls -l "$_d/lib/arm64-v8a" 2>&1 | sed "s/^/[probe] lib: /"
    ls -l "$_d" 2>&1 | sed "s/^/[probe] pkg: /"
  done
  [ "$_hit" = 0 ] && echo "[probe] no directory matched $APP_ROOT/*/$MGR*/"
  echo "---- probe: kernelsu.ko anywhere in the package ----"
  for _d in "$APP_ROOT"/*/"$MGR"*/; do
    [ -d "$_d" ] || continue
    find "$_d" -maxdepth 3 -name "*.ko" 2>/dev/null | while read -r _k; do
      echo "[probe] ko=$(stat -c %s "$_k" 2>/dev/null)B $_k"
    done
  done
  echo "---- probe: on-device leftovers ----"
  # 9.319（用户指令）：/data/adb 不再是任何来源，连探测都不看。
  echo "[probe] pstore=$(ls /sys/fs/pstore 2>/dev/null | wc -l) kernelsu_in_proc_modules=$(grep -c "^kernelsu " /proc/modules 2>/dev/null)"
  echo "---- probe: cli help ----"
  if [ -n "$SRC" ]; then
    echo "[probe] cli=$SRC"
    run_to "$SRC" --version 2>&1 | head -3 | sed "s/^/[probe] ver: /"
    run_to "$SRC" --help 2>&1 | head -40 | sed "s/^/[probe] help: /"
    run_to "$SRC" late-load --help 2>&1 | head -40 | sed "s/^/[probe] late-load help: /"
  else
    echo "[probe] no cli resolved yet (SRC empty)"
  fi
  echo "---- probe: end ----"
}
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
    # package-name 串（它们只认裸 late-load 或别家 flag），以前会因为
    # 这一条把唯一正确的自家 ksud 判掉，然后整条交接 FATAL。
    grep -qa 'late-load' "$_f" 2>/dev/null || continue
    _s=0
    grep -qa 'uapi:' "$_f" 2>/dev/null && _s=$((_s+3))
    grep -qa 'KernelSU version' "$_f" 2>/dev/null && _s=$((_s+3))
    grep -qa 'kernelsu\.ko' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa 'already loaded, skip loading ko' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa 'package-name' "$_f" 2>/dev/null && _s=$((_s+2))
    grep -qa -- '--allow-shell' "$_f" 2>/dev/null && _s=$((_s+1))
    _z=$(wc -c < "$_f" 2>/dev/null | tr -d ' ')
    [ -z "$_z" ] && _z=0
    # 9.291：候选排名要能看见（stdout 被调用方捕获，所以走 stderr），
    # 并且落盘给注册阶段排序用：名字里没有 ksud 的 CLI（libxeccli.so）也能被选中。
    _cpn=0
    grep -qa -- '--package-name' "$_f" 2>/dev/null && _cpn=1
    echo "[resolve] cand $(basename "$_f") score=$_s size=$_z caps=pn$_cpn" >&2
    mkdir -p "$PROBE_DIR" 2>/dev/null
    printf '%s %s %s\n' "$_s" "$_z" "$_f" >> "$PROBE_DIR/candidates.all" 2>/dev/null
    if [ "$_s" -gt "$_bs" ] || { [ "$_s" -eq "$_bs" ] && [ "$_z" -gt "$_bz" ]; }; then
      _best=$_f; _bs=$_s; _bz=$_z
    fi
  done
  [ -n "$_best" ] && { echo "$_best"; return 0; }
  return 1
}

# 9.319（用户指令）：late load 只认所选管理器包，.ko 也要在包内按分数挑。
# 打分：kernelsu 名 +5、ksu 名 +3、*.ko +3、体积大者优先同分。
# 结果写进 KO_PICK / KO_SCORE，供 late-load 阶梯失败后的 insmod 兜底使用，
# 不再去 /data/adb/ksu/lib 捡别家装的模块（那会把内核注册成别人的包名）。
KO_PICK=""
KO_SCORE=0
static_pick_ko() {
  _kbest=""; _kbs=0; _kbz=0
  for _f in "$1"/*.ko; do
    [ -f "$_f" ] || continue
    _s=3
    case "$(basename "$_f")" in
      *kernelsu*) _s=$((_s+5)) ;;
      *ksu*)      _s=$((_s+3)) ;;
    esac
    _z=$(wc -c < "$_f" 2>/dev/null | tr -d ' ')
    [ -z "$_z" ] && _z=0
    echo "[resolve] ko cand $(basename "$_f") score=$_s size=$_z" >&2
    if [ "$_s" -gt "$_kbs" ] || { [ "$_s" -eq "$_kbs" ] && [ "$_z" -gt "$_kbz" ]; }; then
      _kbest=$_f; _kbs=$_s; _kbz=$_z
    fi
  done
  [ -n "$_kbest" ] || return 1
  KO_PICK=$_kbest
  KO_SCORE=$_kbs
  echo "[resolve] ko pick $(basename "$_kbest") score=$_kbs size=$_kbz"
  return 0
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
    static_pick_ko "$d" >/dev/null || true
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
# 9.311：candidates.all 是 static_pick 逐轮**追加**的，以前从不清空 —— 上一轮
# （甚至上一个管理器包）的候选会留在里面，注册阶段按分数取前 6 就可能拿到
# 别家的 CLI 去给自己注册。每轮扫描前必须清空，保证候选只来自本次扫描。
rm -f "$PROBE_DIR/candidates.all" 2>/dev/null
SCAN_N=0
# 9.317：payload 的 uid=0 子进程（in-process 还带 CAP_DAC_*）已经把 /data/app
# 扫过一遍，并把确切 CLI 路径写进 /data/local/tmp/ksu.cli。本机内核在 execve
# 时把 ambient 集合清掉（9.316 真机：CapPrm/CapEff/CapAmb 全 0，只剩 CapInh），
# 所以这个 shell 起来之后 ls /data/app 必然失败，再靠扫描就是死路。
# 9.319（用户指令）：hint 里的路径只有落在所选管理器包内才认。
# payload 是按分数排好序写的（app= / ko= / cli=），这里既取 CLI 也取 KO，
# 任何指向 /data/adb 或别的包的行都被丢弃 —— late load 只可能来自这个包。
CLI_HINT=""
HINT_REJ=0
HINT_FILE=${EXTRACTKIT_HINT_FILE:-/data/local/tmp/ksu.cli}
HINT_DIR=$(sed -n 's/^app=//p' "$HINT_FILE" 2>/dev/null | head -n1)
for _h in ${EXTRACTKIT_KSUD_PATH:-} $(sed -n 's/^cli=//p' "$HINT_FILE" 2>/dev/null); do
  [ -n "$_h" ] || continue
  case "$_h" in
    */"$MGR"*) : ;;
    *) HINT_REJ=$((HINT_REJ + 1)); echo "[resolve] hint rejected (outside package): $_h"; continue ;;
  esac
  [ -f "$_h" ] || continue
  if [ -z "$CLI_HINT" ]; then CLI_HINT=$_h; fi
done
for _k in $(sed -n 's/^ko=//p' "$HINT_FILE" 2>/dev/null); do
  [ -n "$_k" ] || continue
  case "$_k" in
    */"$MGR"*) : ;;
    *) HINT_REJ=$((HINT_REJ + 1)); echo "[resolve] ko hint rejected (outside package): $_k"; continue ;;
  esac
  [ -f "$_k" ] || continue
  [ -z "$KO_PICK" ] && { KO_PICK=$_k; KO_SCORE=hint; }
done
echo "[resolve] hint file=$HINT_FILE cli hint=${CLI_HINT:-none} ko hint=${KO_PICK:-none} rejected=$HINT_REJ"
if [ -n "$CLI_HINT" ]; then
  SRC=$CLI_HINT
  SRC_OWNER=$(stat -c %u "$CLI_HINT" 2>/dev/null)
  SRC_WHY=self
  echo "[resolve] cli from hint: $SRC (skip the $APP_ROOT scan)"
elif [ -n "$HINT_DIR" ] && [ -d "$HINT_DIR" ]; then
  SCAN_N=$((SCAN_N + 1))
  echo "[resolve] scan dir (hint app): $HINT_DIR"
  scan_dir "$HINT_DIR/lib/arm64" "$MGR" self
  scan_dir "$HINT_DIR/lib/arm64-v8a" "$MGR" self
  scan_dir "$HINT_DIR" "$MGR" self
else
  for d in $(ls -d $APP_ROOT/*/"$MGR"*/lib/arm64 2>/dev/null); do
    SCAN_N=$((SCAN_N + 1))
    echo "[resolve] scan dir: $d"
    scan_dir "$d" "$MGR" self
  done
fi
echo "[resolve] scanned $SCAN_N dir(s) for $MGR (cross=0)"

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
    echo "[ksu] not root (uid=$(id -u)): cannot read $APP_ROOT, so the manager ksud cannot be located"
    echo "[ksu] exit=3 (needs the payload su channel; caller must retry through it)"
    leave 3
  fi
  echo "[resolve] mgr=$MGR src= owner= cross=0 why=none"
  # 9.290：XEC 系（com.xecpro.kernel）包内**根本没有** ksud，只有 ghostlock/xeccoresu
  # 这类库，它只读内核状态。这种管理器不可能靠“包内 ksud”被注册，必须说人话。
  echo "[ksu] MGR_NO_CLI: $MGR shipped no late-load-capable binary (scanned $SCAN_N dir(s) under $APP_ROOT/*/$MGR*/lib/arm64; cross=0; 9.204 policy: no cross-package borrow, no /data/adb)"
  # 9.319（用户指令）：包内没有 CLI 就只用包内的 .ko（按分数挑出的 KO_PICK），
  # 不再回退到 /data/local/tmp/ksud —— 那不是这个包的二进制。
  if [ -n "$KO_PICK" ]; then
    echo "[ksu] package ships a module: ko=$KO_PICK score=$KO_SCORE (no CLI, insmod only)"
    echo "[ksu] note: a bare module loads kernelsu but cannot register $MGR's appid"
    SRC=""
    SRC_OWNER=$MGR
    SRC_WHY=ko_only
    KO_ONLY=1
  else
    echo "[ksu] exit=5 (no in-package late-load CLI and no in-package ko; nothing else may be borrowed)"
    leave 5
  fi
fi

# 9.319：包内只带 .ko、没有 CLI 时，直接 insmod 这个包内的模块（走 finit/insmod，
# 不需要 exec 任何东西），不再拼 late-load 阶梯。
if [ "${KO_ONLY:-0}" = 1 ]; then
  CROSS=0
  echo "[resolve] mgr=$MGR src= owner=$SRC_OWNER cross=$CROSS why=$SRC_WHY"
  if [ "$DRYRUN" != 0 ]; then
    echo "[ksu] dryrun: would insmod $KO_PICK (package-local module, score=$KO_SCORE)"
    echo "[resolve] dryrun=1, nothing written (policy: package-local only, no /data/adb)"
    leave 0
  fi
  echo "[ksu] insmod $KO_PICK (package-local module, score=$KO_SCORE)"
  insmod "$KO_PICK" 2>&1 | tail -n 3
  _i=0
  while [ $_i -lt 20 ]; do
    grep -q '^kernelsu ' /proc/modules && break
    _i=$((_i + 1))
    sleep 0.1
  done
  if grep -q '^kernelsu ' /proc/modules; then
    echo KSU_LOADED
    leave 0
  fi
  echo KSU_MISSING
  echo "[ksu] exit=5 (in-package module did not load; nothing outside $MGR is a source)"
  leave 5
fi

CROSS=0
echo "[resolve] mgr=$MGR src=$SRC owner=$SRC_OWNER cross=$CROSS why=$SRC_WHY"
echo "[ksu] source version: $(ver_of "$SRC")"

# 4) 9.320：逐 flag 探测能力。上游 cli.rs 的 LateLoad 只有
#    {magica, allow_shell, post_magica, kmi, package_name} 五个参数，
#    这里只探真正会用到的三个（kmi / allow_shell / package_name）；
#    下面两条阶梯都只拿支持的那几个去拼组合。
CAP_KMI=0; CAP_AS=0; CAP_PN=0
FLAG_OK=0
HELP=""
if [ "$SRC_WHY" = self_static ]; then
  # exec 探测已失败（SIGILL/被 SELinux 挡），拿不到 help。能做的是直接在
  # 二进制里找那些 flag 字符串，比“假设全部支持”准得多。
  HELP="(static)"
  grep -qa -- '--kmi' "$SRC" 2>/dev/null && CAP_KMI=1
  grep -qa -- '--allow-shell' "$SRC" 2>/dev/null && CAP_AS=1
  grep -qa -- '--package-name' "$SRC" 2>/dev/null && CAP_PN=1
  echo "[ksu] static source: flags from binary kmi=$CAP_KMI allow-shell=$CAP_AS package-name=$CAP_PN"
  if [ $((CAP_KMI + CAP_AS + CAP_PN)) -eq 0 ]; then
    CAP_KMI=1; CAP_AS=1; CAP_PN=1
    echo "[ksu] static source: no flag strings found, assume kmi+allow-shell+package-name"
  fi
else
  HELP=$("$SRC" late-load --help 2>&1)
  [ -z "$HELP" ] && HELP=$("$SRC" --help 2>&1)
  echo "$HELP" | grep -q -- '--kmi' && CAP_KMI=1
  echo "$HELP" | grep -q -- '--allow-shell' && CAP_AS=1
  echo "$HELP" | grep -q -- '--package-name' && CAP_PN=1
  # 9.291：有些 CLI 的 --help 不列 late-load 的 flag（XEC 的 xudc 只打 Usage），
  # 直接到二进制里补判，避免把 package-name 丢掉导致注册阶梯退化。
  if [ "$CAP_PN" = 0 ] && grep -qa -- '--package-name' "$SRC" 2>/dev/null; then
    CAP_PN=1
    echo "[cap] package-name via static string (help did not list it)"
  fi
  echo "[ksu] help: $(echo "$HELP" | grep -i -m4 -E 'kmi|package|allow-shell' | tr '
' '|')"
  echo "[ksu] caps kmi=$CAP_KMI allow-shell=$CAP_AS package-name=$CAP_PN"
  if [ $((CAP_KMI + CAP_AS + CAP_PN)) -eq 0 ]; then
    echo "[ksu] warn: --help listed no known late-load flag; ladder will start from bare late-load"
  fi
fi
[ "$CAP_PN" = 1 ] && FLAG_OK=1

# 5) 自检模式：到此为止，不碰 /data/adb
if [ "$DRYRUN" != 0 ]; then
  echo "[resolve] dryrun=1, nothing written (policy: package-local only, no /data/adb)"
  leave 0
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

# 6b) 9.291：CLI 自检 —— 证明这个二进制真的会说 late-load（XEC 的 xudc 打 "xudc <ver> (uapi: 6)"）。
CLI_OK=0
CLI_VER=$("$KSUD" --version 2>&1 | head -n 2 | tr '\n' ' ' | tr -s ' ')
CLI_HELP=$("$KSUD" late-load --help 2>&1 | head -n 3 | tr '\n' ' ' | tr -s ' ')
echo "[resolve] cli: ${CLI_VER:-(empty)}"
echo "[resolve] cli help: ${CLI_HELP:-(empty)}"
case "$CLI_VER $CLI_HELP" in
  *uapi:*|*KernelSU*|*late-load*|*Usage*|*package-name*) CLI_OK=1 ;;
esac
echo "[resolve] cli_ok=$CLI_OK"

# 9.313：真正把「这家管理器的包里有什么」和「它的 CLI 认哪套参数」写进日志。
# 只读探针，任何模式都跑，probe_only 也跑。
probe_assets

if [ "$PROBE_ONLY" = 1 ]; then
  echo "[ksu] probe-only: mgr=$MGR src=$SRC owner=$SRC_OWNER cli=$KSUD cli_ok=$CLI_OK caps=pn$CAP_PN,as$CAP_AS,kmi$CAP_KMI"
  echo "[ksu] probe-only: nothing registered; /data/adb untouched"
  leave 0
fi

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

# 9.357：模块已被 payload 自己加载过时，「带 --package-name 的 late-load」不会再写 appid ——
# ksud 只在 load_module 那一次把 appid 交给内核。上游（tiann/KernelSU userspace/ksud/src/unload.rs
# 与 cli.rs 的 LateLoad）给的办法就是：先 unload，再让自家 ksud 以 --package-name 重新加载。
# 另外 /data/adb/ksu 与 /data/adb/ksu/bin 必须是真目录（不是符号链接/普通文件）并且带
# u:object_r:ksu_file:s0，否则 `ksud install` 会以 "not a regular directory" 失败，
# 按 APK 签名认管理员的构建就永远不会登记这个管理器。
ksu_relabel() {
  _p=$1
  [ -e "$_p" ] || return 0
  if command -v chcon >/dev/null 2>&1; then
    chcon u:object_r:ksu_file:s0 "$_p" 2>/dev/null && return 0
  fi
  return 1
}
repair_adb_tree() {
  echo "[ksu] repair: /data/adb/ksu state"
  for _d in /data/adb/ksu/bin /data/adb/ksu /data/adb/modules; do
    if [ -L "$_d" ]; then echo "[ksu] repair: removing symlink $_d"; rm -f "$_d" 2>/dev/null; fi
    if [ -e "$_d" ] && [ ! -d "$_d" ]; then echo "[ksu] repair: removing non-directory $_d"; rm -f "$_d" 2>/dev/null; fi
  done
  mkdir -p /data/adb/ksu/bin /data/adb/modules 2>/dev/null
  chmod 700 /data/adb/ksu /data/adb/ksu/bin 2>/dev/null
  ls -ld /data/adb/ksu /data/adb/ksu/bin 2>&1 | sed 's/^/[ksu] repair: /'
}
ksu_unload() {
  _bin=$1
  grep -q '^kernelsu ' /proc/modules || { echo "[ksu] unload: module not loaded, skip"; return 0; }
  if ! grep -qa 'unload' "$_bin" 2>/dev/null; then
    echo "[ksu] unload: $(basename "$_bin") has no unload subcommand"
    return 1
  fi
  echo "[ksu] unload: $(basename "$_bin") unload"
  _o=$("$_bin" unload 2>&1); _r=$?
  printf '%s\n' "$_o" | head -n 12 | sed 's/^/[ksu] unload: /'
  echo "[ksu] unload: rc=$_r module_now=$(grep -c '^kernelsu ' /proc/modules)"
  return $_r
}

# 8b) 9.289：只改管理器 appid，不再 insmod。
#     前提：payload 已经 load 了 kernelsu.ko，模块在位但 appid 指向它自己认的包名。
#     判据：管理器自己的 ksud 输出 "set manager appid" 或 rc=0；成功写 mgr_registered 供 verify 读。
if [ "$REGISTER_ONLY" = "1" ]; then
  echo "[ksu] register-only: kernelsu already in /proc/modules (count=$(grep -c '^kernelsu ' /proc/modules))"
  echo "[ksu] register-only: target manager $MGR uid=${MGR_UID_ENV:-?(unknown)}"
  echo "[ksu] register-only: the payload wrote its own appid; our call must override it, nothing else counts"
  repair_adb_tree
  UNLOAD_TRIED=0
  REG_N=0
  REG_OK=0
  REG_HITS=0
  LAST_APPID=""
  UNVER=0
  # 9.311：以前是「先 REG_N+1 再判 >=2」，于是全程只有**一次**真实尝试，
  # 第二次起直接报 budget 耗尽 —— 9.255/9.291 的多 flag 阶梯等于不存在，
  # 第一组 flag 不对就永远注册不上。现在预算覆盖一整条阶梯（默认 8 次），
  # 可用 EXTRACTKIT_REG_MAX 覆盖；耗尽后仍然硬停，避免无限重试。
  REG_MAX=$EXTRACTKIT_REG_MAX
  [ -n "$REG_MAX" ] || REG_MAX=8
  REG_BUDGET=0
  reg_call() {
    _bin=$1
    shift
    if [ "$REG_N" -ge "$REG_MAX" ]; then
      echo "[ksu] register budget exhausted ($REG_MAX attempts) -> stop trying"
      REG_BUDGET=1
      return 6
    fi
    if [ "$UNLOAD_TRIED" = 0 ]; then
      UNLOAD_TRIED=1
      ksu_unload "$_bin"
    fi
    REG_N=$((REG_N + 1))
    echo "[ksu] register try $REG_N: $(basename "$_bin") $*"
    if [ -n "$RUNTO" ]; then _out=$($RUNTO "$_bin" "$@" 2>&1); else _out=$("$_bin" "$@" 2>&1); fi
    _rc=$?
    printf '%s\n' "$_out" | head -n 20 | while IFS= read -r _l; do echo "[ksu]   $_l"; done
    echo "[ksu] register try $REG_N rc=$_rc"
    _first=$(printf '%s\n' "$_out" | sed -n '1p')
    [ -n "$_first" ] && echo "[ksu] register try $REG_N first: $_first"
    _line=$(printf '%s\n' "$_out" | grep -i 'set manager appid' | tail -n 1)
    if [ -n "$_line" ]; then
      REG_HITS=$((REG_HITS + 1))
      echo "[ksu] register try $REG_N appid: $_line"
      _tgt=$(printf '%s\n' "$_line" | sed 's/.*-> *//; s/ *$//')
      # 9.311：只有 "set manager appid: X -> Y" 这种带箭头的行才能靠箭头取到 Y。
      # 有的构建只打 "set manager appid: <pkg>"（没有箭头），那时 _tgt 是整行，
      # 严格相等直接把它判成 rejected —— 于是明明注册成功却继续换 flag 重试。
      # 这里再取一次「最后一个字段」（按空格/冒号切），两种形态都能命中；
      # 仍然只做等值比较，绝不靠子串，免得把 "requested <pkg>" 当成成功。
      _last=$(printf '%s\n' "$_line" | sed 's/.*[ :]//; s/[ ,;].*$//')
      LAST_APPID=$_tgt
      if [ "$_tgt" = "$MGR" ] || [ "$_last" = "$MGR" ]; then
        return 0
      fi
      if [ -n "$MGR_UID_ENV" ] && { [ "$_tgt" = "$MGR_UID_ENV" ] || [ "$_last" = "$MGR_UID_ENV" ]; }; then
        return 0
      fi
      echo "[ksu] register try $REG_N rejected: appid=$_tgt is not $MGR"
      return 1
    fi
    # 9.320: tiann upstream late-load prints no appid line at all -- the
    # manager is recognised by the kernel (throne_tracker + apk signature),
    # and late_load.rs only reports "kernelsu.ko loaded successfully!" or
    # "KernelSU already loaded, skip loading ko".  Accept those two strings
    # when the module is really listed in /proc/modules, instead of demanding
    # a line that build never prints.
    _up=$(printf '%s\n' "$_out" | grep -iE 'kernelsu\.ko loaded successfully|KernelSU already loaded, skip loading ko' | tail -n 1)
    if [ -n "$_up" ]; then
      echo "[ksu] register try $REG_N upstream: $_up"
      if grep -q '^kernelsu ' /proc/modules; then
        LAST_APPID="$MGR (upstream late-load, kernel-side manager tracking)"
        return 0
      fi
      echo "[ksu] register try $REG_N upstream said loaded but /proc/modules has no kernelsu"
    fi
    if [ "$_rc" = 0 ]; then
      echo "[ksu] register try $REG_N rc=0 but no appid line"
      return 2
    fi
    return 1
  }
  # 9.291：每个候选按自己的 flag 能力重试。XEC 的 CLI 是 libxeccli.so，
  # MapleSu 的是 libksud_ksu.so，名字里都没有 ksud，能力面也不一样。
  try_register() {
    _b=$1
    [ "$REG_BUDGET" = 1 ] && { echo "[ksu] register: budget spent, $(basename "$_b") not tried"; return 1; }
    # 9.320: the flag set is copied verbatim from tiann/KernelSU
    # userspace/ksud/src/cli.rs (LateLoad { magica, allow_shell, post_magica,
    # kmi, package_name }).  Two flags are deliberately never passed:
    #  - the uid selector: upstream has no such argument, clap answers
    #  "unexpected argument", so any ladder level carrying it was dead on a
    #  real ksud build and it is gone for good;
    #  - the magica follow-up flag: it only restores adb properties after a
    #  magica late-load (magica::disable_adb_root), it is not a stage
    #  selector.
    _pn=0; _as=0; _r=1
    grep -qa -- '--package-name' "$_b" 2>/dev/null && _pn=1
    grep -qa -- '--allow-shell' "$_b" 2>/dev/null && _as=1
    [ $((_pn + _as)) -eq 0 ] && { _pn=$CAP_PN; _as=$CAP_AS; }
    echo "[ksu] register: candidate $(basename "$_b") flags pn=$_pn allow-shell=$_as"
    if [ "$_pn" = 1 ] && [ "$_as" = 1 ]; then
      reg_call "$_b" late-load --package-name "$MGR" --allow-shell; _r=$?
      [ "$_r" = 0 ] && return 0
    fi
    if [ "$_pn" = 1 ]; then
      reg_call "$_b" late-load --package-name "$MGR"; _rr=$?
      [ "$_rr" = 0 ] && return 0
      [ "$_rr" = 2 ] && _r=2
    fi
    if [ "$_as" = 1 ]; then
      reg_call "$_b" late-load --allow-shell; _rr=$?
      [ "$_rr" = 0 ] && return 0
      [ "$_rr" = 2 ] && _r=2
    fi
    reg_call "$_b" late-load; _rr=$?
    [ "$_rr" = 0 ] && return 0
    [ "$_rr" = 2 ] && _r=2
    [ "$_r" = 2 ] && UNVER=1
    return 1
  }
  CAND_LIST="$KSUD"
  CAND_EXTRA=0
  if [ -f "$PROBE_DIR/candidates.all" ]; then
    for _p in $(sort -rn -k1,1 "$PROBE_DIR/candidates.all" 2>/dev/null | head -n 6 | awk '{print $3}'); do
      [ "$_p" = "$SRC" ] && continue
      case " $CAND_LIST " in *" $_p "*) continue ;; esac
      CAND_LIST="$CAND_LIST $_p"
      CAND_EXTRA=$((CAND_EXTRA + 1))
      [ "$CAND_EXTRA" -ge 3 ] && break
    done
  fi
  echo "[ksu] register: $(printf '%s\n' $CAND_LIST | grep -c .) candidate(s) queued (best first)"
  REG_IDX=0
  for _c in $CAND_LIST; do
    REG_IDX=$((REG_IDX + 1))
    if [ -f "$_c" ] && cp "$_c" "$BIN_DIR/cand$REG_IDX.new" 2>/dev/null && chmod 755 "$BIN_DIR/cand$REG_IDX.new" 2>/dev/null && mv -f "$BIN_DIR/cand$REG_IDX.new" "$BIN_DIR/cand$REG_IDX" 2>/dev/null && is_bin "$BIN_DIR/cand$REG_IDX"; then
      _run="$BIN_DIR/cand$REG_IDX"
    else
      rm -f "$BIN_DIR/cand$REG_IDX.new" 2>/dev/null
      _run=$_c
    fi
    if try_register "$_run"; then
      REG_OK=1
      KSUD=$_run
      echo "[ksu] register: winner $(basename "$_run") after $REG_N attempt(s)"
      break
    fi
  done
  if [ "$REG_OK" = 0 ] && [ "$UNVER" = 1 ]; then
    echo "[ksu] register: rc=0 seen but no verifiable appid line; cannot prove the override"
    echo "[ksu] exit=6 (appid unverified)"
    leave 6
  fi
  if [ "$REG_OK" = 0 ]; then
    echo "[ksu] register: every candidate rejected every flag set; manager appid NOT re-registered"
    echo "[ksu] register: appid lines seen=$REG_HITS last=${LAST_APPID:-none}"
    echo "[ksu] register: help lines mentioning manager:"
    printf '%s\n' "$HELP" | grep -i -m8 -E 'manager|set-manager' | head -n 8 | while IFS= read -r _l; do echo "[ksu]   $_l"; done
    echo "[ksu] exit=4 (register failed)"
    leave 4
  fi
  mkdir -p "$PROBE_DIR" 2>/dev/null
  printf '%s:%s\n' "$MGR" "${MGR_UID_ENV:-?}" > "$PROBE_DIR/mgr_registered" 2>/dev/null
  chmod 0666 "$PROBE_DIR/mgr_registered" 2>/dev/null
  echo "[ksu] manager appid now: ${LAST_APPID:-?} (requested $MGR; payload default replaced by our late-load)"
  echo "[ksu] manager registered: $MGR (${MGR_UID_ENV:-?}) via $(basename "$KSUD")"
  echo 1 > /sys/fs/selinux/enforce 2>/dev/null
  echo "[ksu] enforce=$(getenforce)"
  exit 0
fi

# 8) 已加载就别重复 late-load（包名在加载时定死，换管理器要重启）
if grep -q '^kernelsu ' /proc/modules; then
  echo "KSU_ALREADY"
  repair_adb_tree
  if [ -n "$KSUD" ] && [ -x "$KSUD" ] && ksu_unload "$KSUD"; then
    echo "[ksu] unloaded the preloaded module; re-loading with our manager"
    _r1=$("$KSUD" late-load --package-name "$MGR" --allow-shell 2>&1); _rc1=$?
    printf '%s\n' "$_r1" | head -n 12 | sed 's/^/[ksu]   /'
    echo "[ksu] re-load rc=$_rc1 module_now=$(grep -c '^kernelsu ' /proc/modules)"
    if grep -q '^kernelsu ' /proc/modules; then
      ksu_relabel /data/adb/ksud 2>/dev/null
      echo 1 > /sys/fs/selinux/enforce 2>/dev/null
      echo "[ksu] manager registered by re-load: $MGR (enforce=$(getenforce))"
      exit 0
    fi
  fi
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
# 9.311：整条阶梯必须自己有时间预算。payload 那边等 stage 的上限是 45 s，
# 而这里每层最多 4 s（RUNTO）+ 0.9 s 轮询，8 层就能顶满；没有预算的话
# 一个 hang 住的 ksud 会让 stage 永远不写 done，看起来像「内核不适配」。
STAGE_T0=$(date +%s 2>/dev/null)
[ -n "$STAGE_T0" ] || STAGE_T0=0
stage_elapsed() {
  [ "$STAGE_T0" = 0 ] && { echo 0; return 0; }
  _n=$(date +%s 2>/dev/null)
  [ -n "$_n" ] || { echo 0; return 0; }
  echo $((_n - STAGE_T0))
}
try_load() {
  TRY_N=$((TRY_N + 1))
  _el=$(stage_elapsed)
  if [ "$_el" -ge 30 ]; then
    echo "[ksu] stage time budget spent ($_el s) -> stop the ladder at try=$TRY_N"
    return 1
  fi
  echo "[ksu] late-load try=$TRY_N flags=$* (t+$_el s)"
  # 9.311：以前用 "$KSUD" late-load ... | tail 再读 PIPESTATUS —— ash/mksh 上
  # 没有 PIPESTATUS，LAST_RC 会退化成 tail 的 0（假成功）。改成先取输出再取 rc。
  _out=$("$KSUD" late-load "$@" 2>&1)
  LAST_RC=$?
  printf '%s\n' "$_out" | tail -n 6
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
[ -n "$MGR_UID_ENV" ] && MGR_UID="$MGR_UID_ENV"
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
# 9.320: the uid-selector levels are gone.  tiann/KernelSU
# userspace/ksud/src/cli.rs defines LateLoad with exactly {magica,
# allow_shell, post_magica, kmi, package_name}; clap rejects everything else
# with "unexpected argument", so those three levels could only ever produce a
# non-zero rc on a genuine ksud build.
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
  # 9.319（用户指令）：兜底的 .ko 也只能来自所选管理器包（KO_PICK 由打分得出）。
  KO=$KO_PICK
  if [ -n "$KO" ]; then
    echo "[ksu] fallback=insmod $KO"
    insmod "$KO" 2>&1 | tail -n 3
  fi
  if ! grep -q '^kernelsu ' /proc/modules; then
    safe_restore
    echo "[ksu] FATAL: late-load failed rc=$RC (no ladder level worked; this ksud rejects every flag set we detected)"
    leave 3
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
