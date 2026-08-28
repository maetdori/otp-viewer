# OTPBar — 맥 메뉴바 OTP 뷰어

휴대폰 **Google Authenticator**의 인증 코드를 Mac 메뉴바에서 바로 확인하는 단일 앱입니다.
구글 OTP **내보내기 QR 이미지**를 앱이 직접 디코딩해 계정을 등록하고(별도 웹 도구 불필요),
메뉴바 🔑 아이콘에서 코드를 실시간으로 보여줍니다. 항목을 클릭하면 코드가 복사됩니다.

## 필요한 것
- macOS 13 이상
- (직접 빌드 시) Xcode 또는 Command Line Tools (`xcode-select --install`)

## 설치 (Homebrew, 권장)
```bash
brew install --cask maetdori/tap/otpbar   # /Applications/OTPBar.app 에 설치
open /Applications/OTPBar.app             # 메뉴바에 🔑 아이콘 등장
```
> 서명되지 않은 로컬 빌드라 첫 실행 시 Gatekeeper 경고가 뜨면 Finder에서 **우클릭 → 열기**로 허용하세요.
>
> 제거: `brew uninstall --cask otpbar`

## 직접 빌드 & 실행
```bash
cd ~/source/playground/otp-viewer
chmod +x build-app.sh
./build-app.sh          # 빌드 후 OTPBar.app 생성
open OTPBar.app         # 메뉴바에 🔑 아이콘 등장
```
> 빠르게 테스트만: `swift run`

## 사용법
처음 실행하면 **튜토리얼 창**이 뜹니다. 요약하면:

1. **휴대폰** — Google Authenticator → 우측 상단 메뉴(⋮)/프로필 → 계정 이전(Transfer accounts)
   → 계정 내보내기(Export accounts) → 계정 선택 → QR 코드 표시
2. **캡처** — 그 QR 화면을 캡처(또는 다른 폰·카메라로 촬영)해 Mac으로 옮김
   - ⚠️ 내보내기 화면은 스크린샷이 막혀 있을 수 있어, 그럴 땐 다른 기기로 촬영
3. **Mac** — 메뉴바 🔑 → **QR 이미지에서 가져오기…** → 캡처한 이미지 선택
   → 여러 계정이 한 번에 등록됨

`otpauth://` 단일 계정 QR도 지원합니다. 사용법은 메뉴 **사용법 다시 보기**에서 다시 볼 수 있어요.

## 다국어
시스템 언어에 맞춰 자동 표시되며, 메뉴 **언어(Language)** 에서 직접 바꿀 수 있습니다(선택은 저장됨).
지원: 한국어 · English · 日本語 · 中文 · Español · Deutsch · Français.

## 로그인 시 자동 실행
시스템 설정 → 일반 → 로그인 항목 → `+` → `/Applications/OTPBar.app` 추가.
로그인(또는 재부팅 후 로그인) 시 메뉴바에 자동으로 뜹니다. 끄려면 같은 화면에서 `OTPBar`를 제거하세요.

## 데이터 저장 / 보안
- 계정은 `~/.config/otp-viewer/accounts.json` 에 저장됩니다(시크릿 포함).
- 모든 처리는 로컬에서만 이뤄지고 외부 전송이 없습니다. 이 파일은 이 Mac에만 두세요.
- 로컬 빌드라 처음 실행 시 Gatekeeper 경고가 뜨면 `우클릭 → 열기`로 허용.

## 구현 메모
- TOTP: `CryptoKit` HMAC-SHA1/256/512 (RFC 6238)
- QR 디코딩: CoreImage `CIDetector`
- 내보내기 파싱: `otpauth-migration://` protobuf 직접 디코딩
