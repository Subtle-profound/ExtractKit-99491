#!/bin/sh
# 用一次性 token 把这份 staged 树推到 GitHub，不把凭据写进 .git/config。
#
# 用法（Git Bash）：
#   sh push.sh <TOKEN>
#
# token 权限：Fine-grained → Repository access 里要**勾上 ExtractKit-99491 这个仓库**
#            → Contents: Read and write
# 推完立刻去 GitHub 撤销该 token。

set -e
TOKEN="${1:?用法: sh push.sh <TOKEN>}"
REPO="qq2770355800/ExtractKit-99491"
cd "$(dirname "$0")"

git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$REPO.git"

echo "→ 目标 $REPO，分支 $(git branch --show-current)，提交 $(git rev-parse --short HEAD)"
echo "→ 文件数 $(git ls-files | wc -l)"

git -c credential.helper= push "https://x-access-token:$TOKEN@github.com/$REPO.git" HEAD:main

git remote set-url origin "https://github.com/$REPO.git"
echo "✓ 推送完成：https://github.com/$REPO"
echo "  记得撤销这次用的 token。"
