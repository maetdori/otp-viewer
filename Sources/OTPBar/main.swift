import AppKit
import Combine
import CoreImage
import CryptoKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

// MARK: - 계정 모델
struct Account: Codable {
    let issuer: String
    let name: String?
    let secret: String            // Base32
    let algorithm: String?        // "SHA-1" | "SHA-256" | "SHA-512"
    let digits: Int?
    let period: Int?
}

// MARK: - Base32 (RFC 4648)
private let B32 = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

func base32Decode(_ input: String) -> Data {
    var lookup = [Character: Int]()
    for (i, c) in B32.enumerated() { lookup[c] = i }
    var bits = 0, value = 0
    var out = [UInt8]()
    for ch in input.uppercased() where ch != "=" {
        guard let idx = lookup[ch] else { continue }
        value = (value << 5) | idx
        bits += 5
        if bits >= 8 { out.append(UInt8((value >> (bits - 8)) & 0xff)); bits -= 8 }
    }
    return Data(out)
}

func base32Encode(_ data: Data) -> String {
    var bits = 0, value = 0, out = ""
    for b in data {
        value = (value << 8) | Int(b)
        bits += 8
        while bits >= 5 { out.append(B32[(value >> (bits - 5)) & 31]); bits -= 5 }
    }
    if bits > 0 { out.append(B32[(value << (5 - bits)) & 31]) }
    return out
}

// MARK: - TOTP (RFC 6238)
func totpCode(for account: Account, at time: TimeInterval = Date().timeIntervalSince1970) -> String {
    let digits = account.digits ?? 6
    let period = account.period ?? 30
    let secret = base32Decode(account.secret)
    guard !secret.isEmpty else { return String(repeating: "•", count: digits) }

    var counter = UInt64(time / Double(period)).bigEndian
    let message = withUnsafeBytes(of: &counter) { Data($0) }
    let key = SymmetricKey(data: secret)

    let hash: Data
    switch (account.algorithm ?? "SHA-1").uppercased() {
    case "SHA-256", "SHA256": hash = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    case "SHA-512", "SHA512": hash = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
    default:                  hash = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
    }

    let offset = Int(hash[hash.count - 1] & 0x0f)
    let binary = (UInt32(hash[offset] & 0x7f) << 24)
        | (UInt32(hash[offset + 1]) << 16)
        | (UInt32(hash[offset + 2]) << 8)
        | UInt32(hash[offset + 3])
    let code = binary % UInt32(pow(10.0, Double(digits)))
    return String(format: "%0\(digits)d", code)
}

func spaced(_ code: String) -> String {
    let mid = (code.count + 1) / 2
    let i = code.index(code.startIndex, offsetBy: mid)
    return code[..<i] + " " + code[i...]
}

// MARK: - QR 디코딩 (CoreImage)
func decodeQR(from url: URL) -> [String] {
    guard let image = CIImage(contentsOf: url) else { return [] }
    let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: CIContext(),
                              options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
    let features = detector?.features(in: image) ?? []
    return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }
}

// MARK: - otpauth / migration 파싱
enum OTPParseError: Error { case unsupported }

func parseOTPURI(_ text: String) throws -> [Account] {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.hasPrefix("otpauth-migration://") {
        return try parseMigration(trimmed)
    } else if trimmed.hasPrefix("otpauth://") {
        return [try parseOtpauth(trimmed)]
    }
    throw OTPParseError.unsupported
}

private func parseOtpauth(_ uri: String) throws -> Account {
    guard let comps = URLComponents(string: uri) else { throw OTPParseError.unsupported }
    let q = comps.queryItems ?? []
    func item(_ n: String) -> String? { q.first { $0.name == n }?.value }
    guard let secret = item("secret") else { throw OTPParseError.unsupported }

    var label = comps.path
    if label.hasPrefix("/") { label.removeFirst() }
    label = label.removingPercentEncoding ?? label
    var issuer = item("issuer") ?? ""
    var name = label
    if label.contains(":") {
        let parts = label.split(separator: ":", maxSplits: 1)
        if issuer.isEmpty { issuer = String(parts[0]).trimmingCharacters(in: .whitespaces) }
        name = parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : ""
    }
    let algoMap = ["SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512"]
    return Account(
        issuer: issuer.isEmpty ? label : issuer,
        name: name,
        secret: secret.uppercased().replacingOccurrences(of: " ", with: ""),
        algorithm: algoMap[(item("algorithm") ?? "SHA1").uppercased()] ?? "SHA-1",
        digits: Int(item("digits") ?? "6") ?? 6,
        period: Int(item("period") ?? "30") ?? 30)
}

/// Google Authenticator 내보내기(protobuf) 디코더
private func parseMigration(_ uri: String) throws -> [Account] {
    guard let comps = URLComponents(string: uri),
          var dataValue = comps.queryItems?.first(where: { $0.name == "data" })?.value else {
        throw OTPParseError.unsupported
    }
    dataValue = dataValue.replacingOccurrences(of: " ", with: "+")
    guard let payload = Data(base64Encoded: dataValue) else { throw OTPParseError.unsupported }

    var reader = ProtoReader(payload)
    var accounts: [Account] = []
    while !reader.atEnd {
        let (field, wire) = reader.tag()
        if field == 1 && wire == 2 {                // repeated OtpParameters
            let len = Int(reader.varint())
            let slice = reader.bytes(len)
            if let acc = parseOtpParameters(slice) { accounts.append(acc) }
        } else {
            reader.skip(wire)
        }
    }
    return accounts
}

private func parseOtpParameters(_ data: [UInt8]) -> Account? {
    var reader = ProtoReader(data)
    var secret = Data(), name = "", issuer = ""
    var algorithm = 1, digits = 1
    while !reader.atEnd {
        let (field, wire) = reader.tag()
        switch (field, wire) {
        case (1, 2): secret = Data(reader.bytes(Int(reader.varint())))
        case (2, 2): name = String(decoding: reader.bytes(Int(reader.varint())), as: UTF8.self)
        case (3, 2): issuer = String(decoding: reader.bytes(Int(reader.varint())), as: UTF8.self)
        case (4, 0): algorithm = Int(reader.varint())
        case (5, 0): digits = Int(reader.varint())
        default:     reader.skip(wire)
        }
    }
    guard !secret.isEmpty else { return nil }
    // name이 "Issuer:account" 형태면 issuer/계정으로 분리
    var displayName = name
    if let colon = name.firstIndex(of: ":") {
        if issuer.isEmpty { issuer = String(name[..<colon]).trimmingCharacters(in: .whitespaces) }
        displayName = String(name[name.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
    }
    let algoMap = [1: "SHA-1", 2: "SHA-256", 3: "SHA-512"]
    return Account(
        issuer: issuer.isEmpty ? displayName : issuer,
        name: displayName,
        secret: base32Encode(secret),
        algorithm: algoMap[algorithm] ?? "SHA-1",
        digits: digits == 2 ? 8 : 6,
        period: 30)
}

/// 최소 protobuf 와이어 리더
private struct ProtoReader {
    let bytes: [UInt8]
    var pos = 0
    init(_ d: Data) { bytes = [UInt8](d) }
    init(_ b: [UInt8]) { bytes = b }
    var atEnd: Bool { pos >= bytes.count }
    mutating func varint() -> UInt64 {
        var result: UInt64 = 0, shift: UInt64 = 0
        while pos < bytes.count {
            let b = bytes[pos]; pos += 1
            result |= UInt64(b & 0x7f) << shift
            if b & 0x80 == 0 { break }
            shift += 7
        }
        return result
    }
    mutating func tag() -> (field: Int, wire: Int) {
        let t = varint(); return (Int(t >> 3), Int(t & 7))
    }
    mutating func bytes(_ n: Int) -> [UInt8] {
        let end = min(pos + n, bytes.count)
        defer { pos = end }
        return Array(bytes[pos..<end])
    }
    mutating func skip(_ wire: Int) {
        switch wire {
        case 0: _ = varint()
        case 2: pos += Int(varint())
        case 5: pos += 4
        case 1: pos += 8
        default: break
        }
    }
}

// MARK: - 튜토리얼 (SwiftUI)
struct OnboardingStep {
    let icon, tag, title: String
    var body: String? = nil
    var items: [String]? = nil
    var showImport: Bool = false
}

// MARK: - 다국어(i18n)
enum Lang: String, CaseIterable {
    case ko, en, ja, zh, es, de, fr
    var displayName: String {
        switch self {
        case .ko: return "한국어";   case .en: return "English"; case .ja: return "日本語"
        case .zh: return "中文";     case .es: return "Español"; case .de: return "Deutsch"
        case .fr: return "Français"
        }
    }
    /// 저장된 선택 → 시스템 언어 → 영어 순으로 결정
    static func current() -> Lang {
        if let raw = UserDefaults.standard.string(forKey: "otp_lang"), let l = Lang(rawValue: raw) { return l }
        for id in Locale.preferredLanguages {
            let c = id.lowercased()
            if c.hasPrefix("ko") { return .ko }
            if c.hasPrefix("ja") { return .ja }
            if c.hasPrefix("zh") { return .zh }
            if c.hasPrefix("es") { return .es }
            if c.hasPrefix("de") { return .de }
            if c.hasPrefix("fr") { return .fr }
            if c.hasPrefix("en") { return .en }
        }
        return .en
    }
}

struct Loc {
    // 메뉴
    let tooltip, copyHint, noAccounts, mImport, mHelp, mRefresh, mLanguage, mQuit: String
    // 가져오기 / 알림
    let panelMessage, panelPrompt, failTitle, failMsg, doneTitle, doneMsgFmt, alreadyMsg: String
    // 튜토리얼 창
    let windowTitle, btnPrev, btnNext, btnImport, btnSkip: String
    // 계정 편집
    let mEdit, editSave, editCancel, editIssuer, editName: String
    let steps: [OnboardingStep]
    func doneMsg(_ n: Int) -> String { String(format: doneMsgFmt, n) }
}

let LOC: [Lang: Loc] = [
    .ko: Loc(
        tooltip: "OTP 코드", copyHint: "클릭하면 코드가 복사됩니다", noAccounts: "⚠︎ 등록된 계정이 없습니다",
        mImport: "QR 이미지에서 가져오기…", mHelp: "사용법 다시 보기", mRefresh: "새로고침",
        mLanguage: "언어", mQuit: "종료",
        panelMessage: "구글 OTP 내보내기 QR을 캡처한 이미지를 선택하세요", panelPrompt: "가져오기",
        failTitle: "가져오기 실패", failMsg: "이미지에서 계정을 찾지 못했습니다.\nQR이 선명하게 나온 이미지인지 확인하세요.",
        doneTitle: "가져오기 완료", doneMsgFmt: "%d개 계정을 등록했습니다.", alreadyMsg: "이미 등록된 계정입니다.",
        windowTitle: "OTP 사용법", btnPrev: "이전", btnNext: "다음", btnImport: "QR 이미지 가져오기", btnSkip: "건너뛰기",
        mEdit: "계정 편집…", editSave: "저장", editCancel: "취소", editIssuer: "서비스 이름", editName: "계정",
        steps: [
            .init(icon: "🔐", tag: "", title: "Mac에서 OTP 코드 보기",
                  body: "휴대폰 **Google Authenticator**의 인증 코드를 이 Mac에서 바로 확인할 수 있어요."),
            .init(icon: "📱", tag: "STEP 1 · 휴대폰", title: "구글 OTP에서 계정 내보내기",
                  items: ["**Google Authenticator** 앱 열기",
                          "우측 상단 **메뉴(⋮)** 또는 프로필 아이콘 탭",
                          "**계정 이전**(Transfer accounts) → **계정 내보내기**(Export accounts)",
                          "옮길 계정 선택 → **다음** → **QR 코드** 표시"]),
            .init(icon: "📷", tag: "STEP 2 · 캡처 & 업로드", title: "QR 캡처해서 올리기",
                  body: "QR 화면을 **캡처**한 뒤, 아래 버튼으로 이미지를 올리면 **여러 계정이 한 번에** 등록돼요.\n\n⚠️ 이 화면은 스크린샷이 막혀 있을 수 있어요. 그럴 땐 **다른 폰·카메라로 촬영**해 사진을 Mac으로 옮긴 뒤 올리세요.", showImport: true),
            .init(icon: "🎉", tag: "완료", title: "이제 코드가 보여요",
                  body: "메뉴바 🔑 를 누르면 코드가 실시간으로 뜨고, **항목을 클릭하면 복사**돼요.")
        ]),
    .en: Loc(
        tooltip: "OTP codes", copyHint: "Click to copy the code", noAccounts: "⚠︎ No accounts yet",
        mImport: "Import from QR image…", mHelp: "Show tutorial again", mRefresh: "Refresh",
        mLanguage: "Language", mQuit: "Quit",
        panelMessage: "Choose a screenshot of your Google Authenticator export QR", panelPrompt: "Import",
        failTitle: "Import failed", failMsg: "No accounts were found in the image.\nMake sure the QR code is clear.",
        doneTitle: "Import complete", doneMsgFmt: "Added %d account(s).", alreadyMsg: "These accounts are already registered.",
        windowTitle: "How to use OTP", btnPrev: "Back", btnNext: "Next", btnImport: "Import QR image", btnSkip: "Skip",
        mEdit: "Edit accounts…", editSave: "Save", editCancel: "Cancel", editIssuer: "Service", editName: "Account",
        steps: [
            .init(icon: "🔐", tag: "", title: "See OTP codes on your Mac",
                  body: "View the codes from **Google Authenticator** on your phone right here on your Mac."),
            .init(icon: "📱", tag: "STEP 1 · Phone", title: "Export accounts from Google OTP",
                  items: ["Open **Google Authenticator**",
                          "Tap the **menu (⋮)** or profile icon, top-right",
                          "**Transfer accounts** → **Export accounts**",
                          "Select accounts → **Next** → a **QR code** appears"]),
            .init(icon: "📷", tag: "STEP 2 · Capture & upload", title: "Capture the QR and upload it",
                  body: "**Capture** the QR screen, then upload the image with the button below — **all accounts import at once**.\n\n⚠️ This screen may block screenshots. If so, **photograph it with another phone/camera**, move the photo to your Mac, and upload it here.", showImport: true),
            .init(icon: "🎉", tag: "Done", title: "Your codes are ready",
                  body: "Click the menu bar 🔑 to see codes live — **click an item to copy** it.")
        ]),
    .ja: Loc(
        tooltip: "OTPコード", copyHint: "クリックでコードをコピー", noAccounts: "⚠︎ 登録済みのアカウントがありません",
        mImport: "QR画像から読み込む…", mHelp: "使い方をもう一度見る", mRefresh: "更新",
        mLanguage: "言語", mQuit: "終了",
        panelMessage: "Google OTP書き出しQRのスクリーンショットを選択してください", panelPrompt: "読み込む",
        failTitle: "読み込み失敗", failMsg: "画像からアカウントを検出できませんでした。\nQRコードが鮮明な画像か確認してください。",
        doneTitle: "読み込み完了", doneMsgFmt: "%d件のアカウントを登録しました。", alreadyMsg: "すでに登録済みのアカウントです。",
        windowTitle: "OTPの使い方", btnPrev: "戻る", btnNext: "次へ", btnImport: "QR画像を読み込む", btnSkip: "スキップ",
        mEdit: "アカウントを編集…", editSave: "保存", editCancel: "キャンセル", editIssuer: "サービス名", editName: "アカウント",
        steps: [
            .init(icon: "🔐", tag: "", title: "MacでOTPコードを見る",
                  body: "スマホの **Google Authenticator** の認証コードを、この Mac ですぐに確認できます。"),
            .init(icon: "📱", tag: "STEP 1 · スマホ", title: "Google OTPからアカウントを書き出す",
                  items: ["**Google Authenticator** を開く",
                          "右上の **メニュー(⋮)** またはプロフィールアイコンをタップ",
                          "**アカウントの移行**(Transfer accounts) → **アカウントの書き出し**(Export accounts)",
                          "アカウントを選択 → **次へ** → **QRコード** が表示される"]),
            .init(icon: "📷", tag: "STEP 2 · 撮影とアップロード", title: "QRを撮ってアップロード",
                  body: "QR画面を **キャプチャ** し、下のボタンで画像をアップロードすると **複数アカウントを一括** 登録します。\n\n⚠️ この画面はスクリーンショットが禁止されている場合があります。その場合は **別のスマホ・カメラで撮影** し、写真を Mac に移してからアップロードしてください。", showImport: true),
            .init(icon: "🎉", tag: "完了", title: "コードの準備ができました",
                  body: "メニューバーの 🔑 を押すとコードがリアルタイムで表示され、**項目をクリックするとコピー** できます。")
        ]),
    .zh: Loc(
        tooltip: "OTP 验证码", copyHint: "点按即可复制验证码", noAccounts: "⚠︎ 尚无账户",
        mImport: "从二维码图片导入…", mHelp: "重新查看使用说明", mRefresh: "刷新",
        mLanguage: "语言", mQuit: "退出",
        panelMessage: "请选择谷歌 OTP 导出二维码的截图", panelPrompt: "导入",
        failTitle: "导入失败", failMsg: "未能从图片中找到账户。\n请确认二维码清晰。",
        doneTitle: "导入完成", doneMsgFmt: "已添加 %d 个账户。", alreadyMsg: "这些账户已存在。",
        windowTitle: "OTP 使用说明", btnPrev: "上一步", btnNext: "下一步", btnImport: "导入二维码图片", btnSkip: "跳过",
        mEdit: "编辑账户…", editSave: "保存", editCancel: "取消", editIssuer: "服务名称", editName: "账户",
        steps: [
            .init(icon: "🔐", tag: "", title: "在 Mac 上查看 OTP 验证码",
                  body: "在这台 Mac 上直接查看手机 **Google Authenticator** 的验证码。"),
            .init(icon: "📱", tag: "STEP 1 · 手机", title: "从谷歌 OTP 导出账户",
                  items: ["打开 **Google Authenticator**",
                          "点按右上角的 **菜单(⋮)** 或头像图标",
                          "**转移账户**(Transfer accounts) → **导出账户**(Export accounts)",
                          "选择账户 → **下一步** → 显示 **二维码**"]),
            .init(icon: "📷", tag: "STEP 2 · 截图并上传", title: "截图二维码并上传",
                  body: "**截图** 二维码画面，再用下方按钮上传图片，即可 **一次性导入多个账户**。\n\n⚠️ 该画面可能禁止截图。若如此，请 **用另一部手机/相机拍下**，把照片传到 Mac 后再上传。", showImport: true),
            .init(icon: "🎉", tag: "完成", title: "验证码已就绪",
                  body: "点击菜单栏 🔑 可实时查看验证码，**点按条目即可复制**。")
        ]),
    .es: Loc(
        tooltip: "Códigos OTP", copyHint: "Haz clic para copiar el código", noAccounts: "⚠︎ Aún no hay cuentas",
        mImport: "Importar desde imagen QR…", mHelp: "Ver el tutorial otra vez", mRefresh: "Actualizar",
        mLanguage: "Idioma", mQuit: "Salir",
        panelMessage: "Elige una captura del QR de exportación de Google OTP", panelPrompt: "Importar",
        failTitle: "Error de importación", failMsg: "No se encontraron cuentas en la imagen.\nAsegúrate de que el código QR sea nítido.",
        doneTitle: "Importación completada", doneMsgFmt: "Se añadieron %d cuenta(s).", alreadyMsg: "Estas cuentas ya están registradas.",
        windowTitle: "Cómo usar OTP", btnPrev: "Atrás", btnNext: "Siguiente", btnImport: "Importar imagen QR", btnSkip: "Omitir",
        mEdit: "Editar cuentas…", editSave: "Guardar", editCancel: "Cancelar", editIssuer: "Servicio", editName: "Cuenta",
        steps: [
            .init(icon: "🔐", tag: "", title: "Ve tus códigos OTP en el Mac",
                  body: "Consulta en este Mac los códigos de **Google Authenticator** de tu teléfono."),
            .init(icon: "📱", tag: "PASO 1 · Teléfono", title: "Exporta cuentas de Google OTP",
                  items: ["Abre **Google Authenticator**",
                          "Toca el **menú (⋮)** o el icono de perfil, arriba a la derecha",
                          "**Transferir cuentas** → **Exportar cuentas**",
                          "Selecciona cuentas → **Siguiente** → aparece un **código QR**"]),
            .init(icon: "📷", tag: "PASO 2 · Captura y subida", title: "Captura el QR y súbelo",
                  body: "**Captura** la pantalla del QR y súbela con el botón de abajo: **todas las cuentas se importan a la vez**.\n\n⚠️ Esta pantalla puede bloquear las capturas. Si es así, **fotografíala con otro teléfono o cámara**, pasa la foto al Mac y súbela aquí.", showImport: true),
            .init(icon: "🎉", tag: "Listo", title: "Tus códigos están listos",
                  body: "Haz clic en 🔑 en la barra de menús para ver los códigos en vivo; **haz clic en un elemento para copiarlo**.")
        ]),
    .de: Loc(
        tooltip: "OTP-Codes", copyHint: "Zum Kopieren klicken", noAccounts: "⚠︎ Noch keine Konten",
        mImport: "Aus QR-Bild importieren…", mHelp: "Anleitung erneut ansehen", mRefresh: "Aktualisieren",
        mLanguage: "Sprache", mQuit: "Beenden",
        panelMessage: "Wähle einen Screenshot des Google-OTP-Export-QR", panelPrompt: "Importieren",
        failTitle: "Import fehlgeschlagen", failMsg: "Im Bild wurden keine Konten gefunden.\nStelle sicher, dass der QR-Code scharf ist.",
        doneTitle: "Import abgeschlossen", doneMsgFmt: "%d Konto(en) hinzugefügt.", alreadyMsg: "Diese Konten sind bereits registriert.",
        windowTitle: "OTP verwenden", btnPrev: "Zurück", btnNext: "Weiter", btnImport: "QR-Bild importieren", btnSkip: "Überspringen",
        mEdit: "Konten bearbeiten…", editSave: "Speichern", editCancel: "Abbrechen", editIssuer: "Dienst", editName: "Konto",
        steps: [
            .init(icon: "🔐", tag: "", title: "OTP-Codes auf dem Mac ansehen",
                  body: "Sieh dir die Codes aus **Google Authenticator** auf deinem Handy direkt hier am Mac an."),
            .init(icon: "📱", tag: "SCHRITT 1 · Handy", title: "Konten aus Google OTP exportieren",
                  items: ["**Google Authenticator** öffnen",
                          "Oben rechts auf das **Menü (⋮)** oder Profilsymbol tippen",
                          "**Konten übertragen** → **Konten exportieren**",
                          "Konten auswählen → **Weiter** → ein **QR-Code** erscheint"]),
            .init(icon: "📷", tag: "SCHRITT 2 · Aufnehmen & hochladen", title: "QR aufnehmen und hochladen",
                  body: "**Nimm** den QR-Bildschirm auf und lade das Bild mit der Schaltfläche unten hoch — **alle Konten werden auf einmal importiert**.\n\n⚠️ Dieser Bildschirm blockiert evtl. Screenshots. Dann **fotografiere ihn mit einem anderen Handy/einer Kamera**, übertrage das Foto auf den Mac und lade es hier hoch.", showImport: true),
            .init(icon: "🎉", tag: "Fertig", title: "Deine Codes sind bereit",
                  body: "Klicke in der Menüleiste auf 🔑, um Codes live zu sehen — **klicke einen Eintrag an, um ihn zu kopieren**.")
        ]),
    .fr: Loc(
        tooltip: "Codes OTP", copyHint: "Cliquez pour copier le code", noAccounts: "⚠︎ Aucun compte pour l'instant",
        mImport: "Importer depuis une image QR…", mHelp: "Revoir le tutoriel", mRefresh: "Actualiser",
        mLanguage: "Langue", mQuit: "Quitter",
        panelMessage: "Choisissez une capture du QR d'exportation de Google OTP", panelPrompt: "Importer",
        failTitle: "Échec de l'importation", failMsg: "Aucun compte trouvé dans l'image.\nAssurez-vous que le code QR est net.",
        doneTitle: "Importation terminée", doneMsgFmt: "%d compte(s) ajouté(s).", alreadyMsg: "Ces comptes sont déjà enregistrés.",
        windowTitle: "Utiliser OTP", btnPrev: "Retour", btnNext: "Suivant", btnImport: "Importer une image QR", btnSkip: "Passer",
        mEdit: "Modifier les comptes…", editSave: "Enregistrer", editCancel: "Annuler", editIssuer: "Service", editName: "Compte",
        steps: [
            .init(icon: "🔐", tag: "", title: "Voir les codes OTP sur le Mac",
                  body: "Consultez sur ce Mac les codes de **Google Authenticator** de votre téléphone."),
            .init(icon: "📱", tag: "ÉTAPE 1 · Téléphone", title: "Exporter les comptes de Google OTP",
                  items: ["Ouvrez **Google Authenticator**",
                          "Touchez le **menu (⋮)** ou l'icône de profil, en haut à droite",
                          "**Transférer les comptes** → **Exporter les comptes**",
                          "Sélectionnez des comptes → **Suivant** → un **code QR** apparaît"]),
            .init(icon: "📷", tag: "ÉTAPE 2 · Capture et import", title: "Capturez le QR et importez-le",
                  body: "**Capturez** l'écran du QR, puis importez l'image avec le bouton ci-dessous — **tous les comptes sont importés d'un coup**.\n\n⚠️ Cet écran peut bloquer les captures. Dans ce cas, **photographiez-le avec un autre téléphone/appareil**, transférez la photo sur le Mac et importez-la ici.", showImport: true),
            .init(icon: "🎉", tag: "Terminé", title: "Vos codes sont prêts",
                  body: "Cliquez sur 🔑 dans la barre des menus pour voir les codes en direct — **cliquez sur un élément pour le copier**.")
        ])
]

extension Color { init(hex: UInt) {
    self.init(.sRGB, red: Double((hex >> 16) & 0xff) / 255,
              green: Double((hex >> 8) & 0xff) / 255, blue: Double(hex & 0xff) / 255)
}}

/// 언어(및 그에 따른 문자열)를 담는 반응형 상태
final class AppState: ObservableObject {
    @Published var lang: Lang
    @Published var step: Int = 0
    @Published var lastImported: Int? = nil   // 튜토리얼 내 업로드 결과 (nil=아직)
    init(_ l: Lang) { lang = l }
    var loc: Loc { LOC[lang] ?? LOC[.en]! }
}

struct OnboardingView: View {
    @ObservedObject var state: AppState
    let onSelectLang: (Lang) -> Void
    let onImport: () -> Void
    let onSkip: () -> Void

    /// 완료 단계에서 업로드 결과가 있으면 성공 문구를 앞에 붙인다
    private func bodyText(_ step: OnboardingStep, last: Bool, loc: Loc) -> String {
        var text = step.body ?? ""
        if last, let n = state.lastImported {
            let head = n > 0 ? loc.doneMsg(n) : loc.alreadyMsg
            text = "✅ **\(head)**\n\n" + text
        }
        return text
    }

    var body: some View {
        let loc = state.loc
        let steps = loc.steps
        let idx = min(state.step, steps.count - 1)
        let step = steps[idx]
        let last = idx >= steps.count - 1
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Menu {
                    ForEach(Lang.allCases, id: \.self) { l in
                        Button { onSelectLang(l) } label: {
                            if l == state.lang { Label(l.displayName, systemImage: "checkmark") }
                            else { Text(l.displayName) }
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "globe")
                        Text(state.lang.displayName)
                    }.font(.system(size: 12))
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            .padding(.top, 12).padding(.trailing, 16)

            ZStack {
                RoundedRectangle(cornerRadius: 22)
                    .fill(LinearGradient(colors: [Color(hex: 0x3b82f6), Color(hex: 0x22d3ee)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 88, height: 88)
                Text(step.icon).font(.system(size: 42))
            }
            .padding(.top, 6).padding(.bottom, 18)

            if !step.tag.isEmpty {
                Text(step.tag).font(.system(size: 12, weight: .semibold))
                    .foregroundColor(Color(hex: 0x22d3ee)).padding(.bottom, 4)
            }
            Text(step.title).font(.system(size: 18, weight: .bold)).padding(.bottom, 14)

            Group {
                if let items = step.items {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(items.indices, id: \.self) { i in
                            HStack(alignment: .firstTextBaseline, spacing: 7) {
                                Text("\(i + 1).")
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(.secondary)
                                    .frame(width: 15, alignment: .trailing)
                                Text(.init(items[i]))
                                    .font(.system(size: 13))
                                    .foregroundColor(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                } else {
                    Text(.init(bodyText(step, last: last, loc: loc)))
                        .font(.system(size: 13))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.leading)
                        .lineSpacing(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 11).fill(Color.primary.opacity(0.06)))
            .padding(.horizontal, 24)

            // 업로드 단계: 여기서 바로 QR 이미지 선택
            if step.showImport {
                Button(action: onImport) {
                    Label(loc.btnImport, systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 14)
            }

            HStack(spacing: 7) {
                ForEach(0..<steps.count, id: \.self) { i in
                    Capsule().fill(i == idx ? Color(hex: 0x22d3ee) : Color.secondary.opacity(0.35))
                        .frame(width: i == idx ? 20 : 7, height: 7)
                        .onTapGesture { state.step = i }
                }
            }.padding(.vertical, 20)

            HStack(spacing: 10) {
                if idx > 0 { Button(loc.btnPrev) { state.step -= 1 } }
                if last {
                    Button(step.tag.isEmpty ? loc.btnSkip : step.tag) { onSkip() }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button(loc.btnNext) { state.step += 1 }
                        .keyboardShortcut(.defaultAction)
                }
            }

            if !last {
                Button(loc.btnSkip) { onSkip() }
                    .buttonStyle(.plain).font(.system(size: 12)).foregroundColor(.secondary)
                    .padding(.top, 12)
            }
        }
        .padding(.bottom, 18)
        .frame(width: 470)
    }
}

// MARK: - 계정 편집 (SwiftUI)
struct EditRow: Identifiable {
    let id = UUID()
    var issuer: String
    var name: String
    let secret: String
    let algorithm: String?
    let digits: Int?
    let period: Int?
    var previewCode: String {
        spaced(totpCode(for: Account(issuer: issuer, name: name, secret: secret,
                                     algorithm: algorithm, digits: digits, period: period)))
    }
}

struct AccountsEditorView: View {
    @State var rows: [EditRow]
    let loc: Loc
    let onSave: ([Account]) -> Void
    let onClose: () -> Void

    private func field(_ label: String, _ text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.system(size: 10, weight: .semibold))
                .foregroundColor(.secondary).textCase(.uppercase)
            TextField(label, text: text).textFieldStyle(.roundedBorder)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 3) {
                Text(loc.mEdit.replacingOccurrences(of: "…", with: ""))
                    .font(.system(size: 15, weight: .bold))
                Text("\(loc.editIssuer) / \(loc.editName)")
                    .font(.system(size: 11)).foregroundColor(.secondary)
            }
            .padding(.top, 16).padding(.bottom, 12)

            List {
                ForEach($rows) { $row in
                    HStack(alignment: .center, spacing: 10) {
                        Image(systemName: "line.3.horizontal")
                            .font(.system(size: 12))
                            .foregroundColor(.secondary.opacity(0.5))
                        VStack(spacing: 8) {
                            field(loc.editIssuer, $row.issuer)
                            field(loc.editName, $row.name)
                        }
                        VStack(spacing: 10) {
                            Text(row.previewCode)
                                .font(.system(size: 13, weight: .medium, design: .monospaced))
                                .foregroundColor(Color(hex: 0x22d3ee))
                            Button { rows.removeAll { $0.id == row.id } } label: {
                                Image(systemName: "trash").font(.system(size: 13))
                            }
                            .buttonStyle(.borderless)
                            .foregroundColor(Color(hex: 0xf85149))
                        }
                        .frame(width: 78)
                    }
                    .padding(12)
                    .background(RoundedRectangle(cornerRadius: 10)
                        .fill(Color.primary.opacity(0.05)))
                    .listRowSeparator(.hidden)
                    .listRowInsets(EdgeInsets(top: 5, leading: 16, bottom: 5, trailing: 16))
                    .listRowBackground(Color.clear)
                }
                .onMove { rows.move(fromOffsets: $0, toOffset: $1) }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)

            Divider()
            HStack {
                Button(loc.editCancel) { onClose() }
                    .controlSize(.large)
                Spacer()
                Button(loc.editSave) {
                    onSave(rows.map {
                        Account(issuer: $0.issuer.isEmpty ? $0.name : $0.issuer,
                                name: $0.name, secret: $0.secret,
                                algorithm: $0.algorithm, digits: $0.digits, period: $0.period)
                    })
                }
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(minWidth: 500, minHeight: 380)
    }
}

// MARK: - 메뉴바 앱
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private let menu = NSMenu()
    private var accounts: [Account] = []
    private var codeItems: [NSMenuItem] = []
    private var onboardingWindow: NSWindow?
    private var onboardingHosting: NSHostingController<OnboardingView>?
    private var editorWindow: NSWindow?
    private let appState = AppState(Lang.current())
    private var lang: Lang { appState.lang }
    private var L: Loc { appState.loc }

    private var accountsURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/otp-viewer/accounts.json")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "OTP")
        statusItem.button?.toolTip = L.tooltip
        statusItem.menu = menu

        accounts = loadAccounts()
        buildMenu()
        updateTitles()

        let timer = Timer(timeInterval: 1, target: self, selector: #selector(tick), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)

        if accounts.isEmpty { showOnboarding() }   // 첫 실행 튜토리얼
    }

    private func loadAccounts() -> [Account] {
        guard let data = try? Data(contentsOf: accountsURL) else { return [] }
        return (try? JSONDecoder().decode([Account].self, from: data)) ?? []
    }

    private func saveAccounts() {
        try? FileManager.default.createDirectory(
            at: accountsURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let data = try? JSONEncoder().encode(accounts) { try? data.write(to: accountsURL) }
    }

    private func buildMenu() {
        menu.removeAllItems()
        codeItems.removeAll()

        if accounts.isEmpty {
            let warn = NSMenuItem(title: L.noAccounts, action: nil, keyEquivalent: "")
            warn.isEnabled = false
            menu.addItem(warn)
        } else {
            let header = NSMenuItem(title: L.copyHint, action: nil, keyEquivalent: "")
            header.isEnabled = false
            menu.addItem(header)
            for (i, _) in accounts.enumerated() {
                let item = NSMenuItem(title: "", action: #selector(copyCode(_:)), keyEquivalent: "")
                item.target = self
                item.tag = i
                menu.addItem(item)
                codeItems.append(item)
            }
        }

        menu.addItem(.separator())
        let imp = menu.addItem(withTitle: L.mImport, action: #selector(importQR), keyEquivalent: "i")
        imp.target = self
        if !accounts.isEmpty {
            let edit = menu.addItem(withTitle: L.mEdit, action: #selector(showEditor), keyEquivalent: "e")
            edit.target = self
        }
        let help = menu.addItem(withTitle: L.mHelp, action: #selector(showOnboarding), keyEquivalent: "")
        help.target = self
        let ref = menu.addItem(withTitle: L.mRefresh, action: #selector(reload), keyEquivalent: "r")
        ref.target = self

        // 언어 선택 서브메뉴
        let langItem = NSMenuItem(title: L.mLanguage, action: nil, keyEquivalent: "")
        let langMenu = NSMenu()
        for l in Lang.allCases {
            let mi = NSMenuItem(title: l.displayName, action: #selector(setLang(_:)), keyEquivalent: "")
            mi.target = self
            mi.representedObject = l.rawValue
            mi.state = (l == lang) ? .on : .off
            langMenu.addItem(mi)
        }
        menu.addItem(langItem)
        menu.setSubmenu(langMenu, for: langItem)

        menu.addItem(.separator())
        let quit = menu.addItem(withTitle: L.mQuit, action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
    }

    @objc private func setLang(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String, let l = Lang(rawValue: raw) else { return }
        applyLang(l)
    }

    /// 메뉴·튜토리얼 창 어디서 바꿔도 공통으로 적용 (튜토리얼은 반응형이라 단계 유지)
    private func applyLang(_ l: Lang) {
        appState.lang = l
        UserDefaults.standard.set(l.rawValue, forKey: "otp_lang")
        statusItem.button?.toolTip = L.tooltip
        onboardingWindow?.title = L.windowTitle
        buildMenu()
        updateTitles()
    }

    @objc private func tick() { updateTitles() }

    private func displayName(_ a: Account) -> String {
        if let n = a.name, !n.isEmpty { return "\(a.issuer) (\(n))" }
        return a.issuer
    }

    private func updateTitles() {
        guard !accounts.isEmpty else { return }
        let now = Date().timeIntervalSince1970
        let font = NSFont.menuFont(ofSize: 0)
        func width(_ s: String) -> CGFloat { (s as NSString).size(withAttributes: [.font: font]).width }

        // 3열 정렬: [계정] \t [코드] \t [초]
        var maxName: CGFloat = 0, maxCode: CGFloat = 0
        for a in accounts {
            maxName = max(maxName, width(displayName(a)))
            maxCode = max(maxCode, width(spaced(String(repeating: "8", count: a.digits ?? 6))))
        }
        let codeTab = maxName + 24                       // 코드 열: 왼쪽 정렬
        let secTab  = codeTab + maxCode + 20 + width("59s") // 초 열: 오른쪽 정렬

        let ps = NSMutableParagraphStyle()
        ps.tabStops = [
            NSTextTab(textAlignment: .left,  location: codeTab),
            NSTextTab(textAlignment: .right, location: secTab)
        ]
        // 색은 지정하지 않아 선택 시 하이라이트 반전이 유지됨
        let attrs: [NSAttributedString.Key: Any] = [.paragraphStyle: ps, .font: font]

        for (i, item) in codeItems.enumerated() where i < accounts.count {
            let a = accounts[i]
            let period = a.period ?? 30
            let remain = period - Int(now) % period
            let text = "\(displayName(a))\t\(spaced(totpCode(for: a)))\t\(remain)s"
            item.attributedTitle = NSAttributedString(string: text, attributes: attrs)
        }
    }

    @objc private func copyCode(_ sender: NSMenuItem) {
        guard sender.tag < accounts.count else { return }
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(totpCode(for: accounts[sender.tag]), forType: .string)
    }

    // MARK: 가져오기
    @objc private func importQR() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = true
        panel.message = L.panelMessage
        panel.prompt = L.panelPrompt
        guard panel.runModal() == .OK else { return }

        var imported: [Account] = []
        for url in panel.urls {
            for text in decodeQR(from: url) {
                if let accs = try? parseOTPURI(text) { imported.append(contentsOf: accs) }
            }
        }
        finishImport(imported)
    }

    private func finishImport(_ imported: [Account]) {
        let onboardingOpen = onboardingWindow?.isVisible == true
        guard !imported.isEmpty else {
            alert(L.failTitle, L.failMsg)   // 실패 시 현재 단계 유지
            return
        }
        var seen = Set(accounts.map(keyOf))
        var added = 0
        for a in imported where !seen.contains(keyOf(a)) {
            accounts.append(a); seen.insert(keyOf(a)); added += 1
        }
        saveAccounts()
        buildMenu()
        updateTitles()
        if onboardingOpen {
            // 창을 닫지 않고 '완료' 단계로 넘어가 결과를 보여준다
            appState.lastImported = added
            appState.step = L.steps.count - 1
        } else {
            alert(L.doneTitle, added > 0 ? L.doneMsg(added) : L.alreadyMsg)
        }
    }

    private func keyOf(_ a: Account) -> String { "\(a.issuer)|\(a.name ?? "")|\(a.secret)" }

    private func alert(_ title: String, _ message: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        a.runModal()
    }

    // MARK: 튜토리얼 창
    private func makeOnboardingView() -> OnboardingView {
        OnboardingView(state: appState,
            onSelectLang: { [weak self] l in self?.applyLang(l) },
            onImport:     { [weak self] in self?.importQR() },
            onSkip:       { [weak self] in self?.onboardingWindow?.close() })
    }

    @objc private func showOnboarding() {
        appState.step = 0
        appState.lastImported = nil
        if onboardingWindow == nil {
            let hosting = NSHostingController(rootView: makeOnboardingView())
            let win = NSWindow(contentViewController: hosting)
            win.title = L.windowTitle
            win.styleMask = [.titled, .closable]
            win.isReleasedWhenClosed = false
            win.center()
            onboardingHosting = hosting
            onboardingWindow = win
        }
        NSApp.activate(ignoringOtherApps: true)
        onboardingWindow?.makeKeyAndOrderFront(nil)
    }

    // MARK: 계정 편집 창
    @objc private func showEditor() {
        let rows = accounts.map {
            EditRow(issuer: $0.issuer, name: $0.name ?? "", secret: $0.secret,
                    algorithm: $0.algorithm, digits: $0.digits, period: $0.period)
        }
        let view = AccountsEditorView(
            rows: rows, loc: L,
            onSave: { [weak self] updated in
                guard let self else { return }
                self.accounts = updated
                self.saveAccounts()
                self.buildMenu()
                self.updateTitles()
                self.editorWindow?.close()
            },
            onClose: { [weak self] in self?.editorWindow?.close() })

        editorWindow?.close()            // 항상 최신 계정으로 새로 연다
        let win = NSWindow(contentViewController: NSHostingController(rootView: view))
        win.title = L.mEdit.replacingOccurrences(of: "…", with: "")
        win.styleMask = [.titled, .closable, .resizable]
        win.isReleasedWhenClosed = false
        win.setContentSize(NSSize(width: 520, height: 540))
        win.center()
        editorWindow = win
        NSApp.activate(ignoringOtherApps: true)
        win.makeKeyAndOrderFront(nil)
    }

    @objc private func reload() {
        accounts = loadAccounts()
        buildMenu()
        updateTitles()
    }

    @objc private func quitApp() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
