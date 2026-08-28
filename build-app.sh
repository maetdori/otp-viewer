#!/bin/bash
# OTPBar 메뉴바 앱을 빌드하고 OTPBar.app 번들로 패키징합니다.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "▶ 빌드 중… (swift build -c release)"
swift build -c release

APP="$DIR/OTPBar.app"
BIN="$DIR/.build/release/OTPBar"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/OTPBar"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>OTPBar</string>
    <key>CFBundleDisplayName</key>     <string>OTP</string>
    <key>CFBundleIdentifier</key>      <string>local.otpbar</string>
    <key>CFBundleExecutable</key>      <string>OTPBar</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>1.0</string>
    <key>LSUIElement</key>             <true/>
    <key>LSMinimumSystemVersion</key>  <string>13.0</string>
</dict>
</plist>
PLIST

echo "✓ 완료: $APP"
echo "  실행하려면: open \"$APP\"   (또는 Finder에서 더블클릭)"
