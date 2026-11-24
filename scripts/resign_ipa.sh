#!/usr/bin/env bash
#
# resign_ipa.sh —— IPA 重签名
#
# 用一条独立的临时 keychain 完成签名, 结束后清理, 不污染默认钥匙串。
#
# 用法:
#   ./resign_ipa.sh <in.ipa> <out.ipa> <cert.p12> <p12密码> <证书名称> <profile.mobileprovision> [新BundleID]
#
# 证书名称用下面这条命令查到:
#   security find-identity -v -p codesigning
#
set -euo pipefail

if [ "$#" -lt 6 ]; then
    sed -n '3,12p' "$0"
    exit 1
fi

IPA="$1"
OUT="$2"
P12="$3"
P12_PASS="$4"
CERT_NAME="$5"
PROVISION="$6"
NEW_BUNDLE_ID="${7:-}"

WORK="$(mktemp -d)"
KEYCHAIN="$WORK/resign.keychain-db"
KEYCHAIN_PASS="resign-tmp"

cleanup() {
    security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "[1/7] 创建临时 keychain"
security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
security import "$P12" -k "$KEYCHAIN" -P "$P12_PASS" \
    -T /usr/bin/codesign -T /usr/bin/security >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "$KEYCHAIN_PASS" "$KEYCHAIN" >/dev/null
ORIGINAL_CHAINS="$(security list-keychains -d user | tr -d '"')"
security list-keychains -d user -s "$KEYCHAIN" $ORIGINAL_CHAINS

echo "[2/7] 解包"
unzip -q "$IPA" -d "$WORK/payload"
APP="$(find "$WORK/payload/Payload" -maxdepth 1 -name '*.app' | head -n 1)"
if [ -z "$APP" ]; then
    echo "错误: Payload 目录下没有 .app" >&2
    exit 1
fi

echo "[3/7] 清理旧签名"
rm -rf "$APP/_CodeSignature"
find "$APP" -name '_CodeSignature' -type d -prune -exec rm -rf {} + 2>/dev/null || true

echo "[4/7] 替换描述文件"
cp "$PROVISION" "$APP/embedded.mobileprovision"

ENT_ARGS=()

if [ -n "$NEW_BUNDLE_ID" ]; then
    echo "[5/7] 改写 Bundle ID -> $NEW_BUNDLE_ID"
    /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $NEW_BUNDLE_ID" \
        "$APP/Info.plist"
else
    echo "[5/7] 保留原 Bundle ID"
fi

echo "[6/7] 提取权限并签名"
security cms -D -i "$PROVISION" > "$WORK/profile.plist"
ENT="$WORK/entitlements.plist"
if /usr/libexec/PlistBuddy -x -c "Print :Entitlements" \
        "$WORK/profile.plist" > "$ENT" 2>/dev/null; then
    ENT_ARGS=(--entitlements "$ENT")
fi

# 嵌套组件必须由内向外先签
while IFS= read -r -d '' item; do
    codesign --force --sign "$CERT_NAME" --timestamp=none \
        --generate-entitlement-der "${ENT_ARGS[@]}" "$item"
done < <(find "$APP" \( -name '*.framework' -o -name '*.dylib' \
        -o -name '*.appex' \) -print0 | sort -zr)

codesign --force --sign "$CERT_NAME" --timestamp=none \
    --generate-entitlement-der "${ENT_ARGS[@]}" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"

echo "[7/7] 打包"
mkdir -p "$WORK/out/Payload"
mv "$APP" "$WORK/out/Payload/"
rm -f "$OUT"
( cd "$WORK/out" && zip -qry "$OUT" Payload )

echo "完成: $OUT"
