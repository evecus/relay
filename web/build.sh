#!/usr/bin/env bash
# 构建 Relay 前端并把产物复制到 src/web/static/ 供 include_dir! 嵌入。
#
# 用法：
#   ./web/build.sh          # 构建 + 复制
#   ./web/build.sh --dev    # 仅安装依赖（不构建，用于开发）
#
# 前置：需要 node + npm。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UI_DIR="$SCRIPT_DIR/ui"
STATIC_DIR="$PROJECT_ROOT/src/web/static"

echo "==> 前端目录: $UI_DIR"
echo "==> 静态资源目标: $STATIC_DIR"

# 1. 检查 node/npm
if ! command -v npm &>/dev/null; then
  echo "错误：未找到 npm，请先安装 Node.js" >&2
  exit 1
fi

# 2. 安装依赖（若 node_modules 不存在）
if [ ! -d "$UI_DIR/node_modules" ]; then
  echo "==> 安装依赖…"
  (cd "$UI_DIR" && npm install)
fi

# 开发模式：只装依赖，不构建
if [ "${1:-}" = "--dev" ]; then
  echo "==> 开发模式：跳过构建"
  echo "    开发服务器: cd $UI_DIR && npm run dev"
  exit 0
fi

# 3. 构建
echo "==> 构建前端…"
(cd "$UI_DIR" && npm run build)

# 4. 复制 dist → src/web/static
echo "==> 复制产物到 $STATIC_DIR …"
mkdir -p "$STATIC_DIR"
# 清除旧内容（保留目录本身）
find "$STATIC_DIR" -mindepth 1 -delete
# 复制新产物
cp -r "$UI_DIR/dist/." "$STATIC_DIR/"

echo "==> 完成。静态资源列表："
ls -la "$STATIC_DIR/"
echo ""
echo "现在可以 cargo build 嵌入最新前端。"
