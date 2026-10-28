// SoftEther for iOS — SwiftUI app (parity with softether_minimum 0.8.x Android).

import SwiftUI
import UIKit
import CoreImage
import NetworkExtension
import SoftEtherCore

let appGroupId = "group.com.jodtados.softether"
let providerBundleId = "com.jodtados.softether.ne"

enum AppModel {
    static var sharedDefaults: UserDefaults { UserDefaults(suiteName: appGroupId) ?? .standard }
    static var store: ServerStore { ServerStore(defaults: sharedDefaults) }
    static var qrSecret: String {
        sharedDefaults.string(forKey: prefServerSecret) ?? ""
    }
}

@main
struct SoftEtherApp: App {
    var body: some Scene {
        WindowGroup {
            MainTabView()
        }
    }
}

struct MainTabView: View {
    @State private var selection = 0

    var body: some View {
        TabView(selection: $selection) {
            NavigationStack { ServerListView() }
                .tabItem { Label("Серверы", systemImage: "list.bullet") }
                .tag(0)

            NavigationStack { SettingsView() }
                .tabItem { Label("Настройки", systemImage: "gearshape") }
                .tag(1)
        }
    }
}

// MARK: - server list (HomeFragment)

struct ServerListView: View {
    @State private var servers: [ServerProfile] = []
    @State private var activeId = ""
    @State private var statusText = ""
    @State private var usedBytes: Double = 0
    @State private var editingProfile: ServerProfile?
    @State private var showScanner = false
    @State private var showLinkDialog = false
    @State private var linkText = ""
    @State private var showEditorForNew = false
    @State private var showExportSheet = false
    @State private var exportToken: String?
    @State private var importMessage: String?
    @State private var statusTimer: Timer?

    private var isConnected: Bool {
        statusText == "Подключено" || statusText == "Подключение…"
            || statusText.hasPrefix("Ротация") || statusText.hasPrefix("Лимит: переключение")
    }

    private var serverList: some View {
        List {
            Section {
                if servers.isEmpty {
                    Text("Нет серверов. Добавьте через QR, ссылку или вручную.")
                        .foregroundColor(.secondary)
                }
                ForEach(servers) { server in
                    Button {
                        if !isConnected {
                            AppModel.store.setActiveServer(server.id, isUserInitiated: true)
                            activeId = server.id
                            VpnManager.shared.connect()
                        }
                    } label: {
                        HStack {
                            Image(systemName: server.id == activeId && isConnected
                                ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(server.id == activeId ? .accentColor : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(server.label.isEmpty ? server.hostname : server.label)
                                    .foregroundColor(.primary)
                                Text("\(server.hostname):\(String(server.port)) · \(server.hub)")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                        }
                    }
                    .swipeActions {
                        Button(role: .destructive) {
                            AppModel.store.deleteServer(id: server.id)
                            reload()
                        } label: { Label("Удалить", systemImage: "trash") }

                        Button {
                            editingProfile = server
                        } label: { Label("Изменить", systemImage: "pencil") }
                    }
                }
            }

            Section {
                if let message = importMessage {
                    Text(message).font(.footnote).foregroundColor(.secondary)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    private var connectButton: some View {
        Button {
            if isConnected {
                VpnManager.shared.disconnect()
            } else if !activeId.isEmpty {
                VpnManager.shared.connect()
            }
        } label: {
            Text(isConnected ? "ОТКЛЮЧИТЬСЯ" : "ПОДКЛЮЧИТЬСЯ")
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
        }
        .buttonStyle(.borderedProminent)
        .disabled(activeId.isEmpty)
        .padding()
    }

    @ViewBuilder private var toolbarMenu: some View {
        Menu {
            Button { showEditorForNew = true } label: { Label("Добавить вручную", systemImage: "keyboard") }
            Button { showScanner = true } label: { Label("Сканировать QR", systemImage: "qrcode.viewfinder") }
            Button { showLinkDialog = true } label: { Label("Добавить по ссылке", systemImage: "link") }
#if !USER_BUILD
            Menu {
                Button("Экспорт всех (QR)") { exportAll() }
                ForEach(servers) { server in
                    Button("QR: \(server.label.isEmpty ? server.hostname : server.label)") {
                        exportProfile(server)
                    }
                }
            } label: { Label("Экспорт QR", systemImage: "arrow.up.doc") }
#endif
        } label: {
            Image(systemName: "ellipsis.circle")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            serverList
            connectButton
        }
        .navigationTitle("SoftEther")
        .toolbar { toolbarMenu }
        .sheet(isPresented: $showScanner) {
            ScannerView { token in
                showScanner = false
                handleToken(token)
            }
        }
        .sheet(item: $editingProfile) { profile in
            NavigationStack { ServerEditorView(profile: profile) }
        }
        .sheet(isPresented: $showEditorForNew) {
            NavigationStack { ServerEditorView(profile: ServerProfile(label: "", hostname: "", hub: "", username: "", password: "")) }
        }
        .sheet(isPresented: $showExportSheet) {
            if let token = exportToken {
                QrExportView(token: token)
            }
        }
        .alert("Добавить по ссылке", isPresented: $showLinkDialog) {
            TextField("vpn://, https:// или host:port", text: $linkText)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button("Добавить") { handleToken(linkText); linkText = "" }
            Button("Отмена", role: .cancel) {}
        } message: {
            Text("Ссылка, токен MVC1 или адрес сервера")
        }
        .onAppear { reload() }
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            refreshStatus()
        }
    }

    private func reload() {
        servers = AppModel.store.loadServers()
        activeId = AppModel.store.activeServerId()
        if activeId.isEmpty, let first = servers.first {
            AppModel.store.setActiveServer(first.id, isUserInitiated: true)
            activeId = first.id
        }
        refreshStatus()
    }

    private func refreshStatus() {
        let text = AppModel.sharedDefaults.string(forKey: prefStatusText) ?? ""
        if text != statusText { statusText = text }
        usedBytes = AppModel.sharedDefaults.double(forKey: prefUsedBytesSnapshot)
        if let session = VpnManager.shared.session {
            if session.status == .connected && !isConnected && statusText.isEmpty {
                statusText = "Подключено"
            }
        }
    }

    private func handleToken(_ raw: String) {
        let key = QrPayload.deriveKey(AppModel.qrSecret)
        if !AppModel.qrSecret.isEmpty,
           let decoded = QrPayload.decode(raw, key: key), !decoded.isEmpty
        {
            // fresh ids: no profile identity leaks through the QR (as on Android)
            let isFirstServer = AppModel.store.loadServers().isEmpty
            var firstId: String?
            for entry in decoded {
                let profile = ServerProfile(
                    label: entry.label.isEmpty ? entry.hostname : entry.label,
                    hostname: entry.hostname, hub: entry.hub, username: entry.username,
                    password: entry.password, port: entry.port,
                    trustedCertPem: entry.certBody.map(QrPayload.pemFromBody)
                )
                firstId = firstId ?? profile.id
                AppModel.store.saveServer(profile)
            }
            if isFirstServer, let firstId {
                AppModel.store.setActiveServer(firstId, isUserInitiated: true)
            }
            importMessage = "Импортировано серверов: \(decoded.count)"
            reload()
            return
        }

        // not our format: offer to keep it as a server link
        if let parsed = ServerLinkParser.parse(raw) {
            editingProfile = ServerProfile(
                label: parsed.hostname ?? "",
                hostname: parsed.hostname ?? "",
                hub: parsed.hub ?? "",
                username: parsed.username ?? "",
                password: parsed.password ?? "",
                port: parsed.port ?? 443
            )
            importMessage = nil
            return
        }

        importMessage = "Не удалось распознать QR/ссылку"
    }

    /// QR capacity ladder, as on Android: full → without cert → too large.
    private func exportTokenOrNull(_ build: (Bool) -> String) -> String? {
        let full = build(true)
        if full.utf8.count <= QrImage.maxChars { return full }
        let withoutCert = build(false)
        if withoutCert.utf8.count <= QrImage.maxChars { return withoutCert }
        return nil
    }

    private func exportProfile(_ server: ServerProfile) {
        let key = QrPayload.deriveKey(AppModel.qrSecret)
        guard !AppModel.qrSecret.isEmpty else {
            importMessage = "Задайте QR-секрет в настройках"
            return
        }
        exportToken = exportTokenOrNull { QrPayload.encode(server, key: key, includeCert: $0) }
        showExportSheet = true
    }

    private func exportAll() {
        let key = QrPayload.deriveKey(AppModel.qrSecret)
        guard !AppModel.qrSecret.isEmpty else {
            importMessage = "Задайте QR-секрет в настройках"
            return
        }
        let list = AppModel.store.loadServers()
        guard !list.isEmpty else { return }
        exportToken = exportTokenOrNull { QrPayload.encodeAll(list, key: key, includeCert: $0) }
        showExportSheet = true
    }
}

// MARK: - server editor

struct ServerEditorView: View {
    @State var profile: ServerProfile
    @Environment(\.dismiss) private var dismiss
    @State private var certText = ""

    var body: some View {
        Form {
            Section("Сервер") {
                TextField("Название", text: $profile.label)
                TextField("Адрес", text: $profile.hostname)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                TextField("Порт", value: $profile.port, format: .number.grouping(.never))
                    .keyboardType(.numberPad)
                TextField("Хаб", text: $profile.hub)
                    .autocorrectionDisabled()
            }

            Section("Учётная запись") {
                TextField("Пользователь", text: $profile.username)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                SecureField("Пароль", text: $profile.password)
            }

            Section {
                TextEditor(text: $certText)
                    .font(.system(.caption, design: .monospaced))
                    .frame(minHeight: 80)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Сертификат сервера (PEM, необязательно)")
            } footer: {
                Text("Оставьте пустым — сертификат будет закреплён автоматически при первом подключении.")
            }
        }
        .navigationTitle(profile.label.isEmpty ? "Новый сервер" : "Сервер")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Отмена") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Сохранить") {
                    let body = certText.trimmingCharacters(in: .whitespacesAndNewlines)
                    profile.trustedCertPem = body.isEmpty ? nil : certText
                    AppModel.store.saveServer(profile)
                    dismiss()
                }
                .disabled(profile.hostname.isEmpty || profile.hub.isEmpty || profile.username.isEmpty)
            }
        }
        .onAppear {
            certText = profile.trustedCertPem ?? ""
        }
    }
}

// MARK: - settings (parity with the Android preference screen)

struct SettingsView: View {
    @State private var sslVersion = ""
    @State private var doSelectSuites = true
    @State private var suites: [String] = []
    @State private var udpEnabled = true
    @State private var mtu = 1500
    @State private var limitEnabled = true
    @State private var limitMB = defaultLimitMB
    @State private var rotationMinutes = 30
    @State private var qrSecret = ""

    private let suiteOptions = [
        "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256",
    ]

    var body: some View {
        Form {
            Section("TLS") {
                Picker("Версия TLS", selection: $sslVersion) {
                    Text("Как на сервере (DEFAULT)").tag("DEFAULT")
                    Text("TLSv1.3").tag("TLSv1.3")
                    Text("TLSv1.2").tag("TLSv1.2")
                }
                Toggle("Выбор шифров", isOn: $doSelectSuites)
                if doSelectSuites {
                    ForEach(suiteOptions, id: \.self) { suite in
                        Toggle(suitesLabel(suite), isOn: Binding(
                            get: { suites.contains(suite) },
                            set: { on in
                                if on { suites.append(suite) } else { suites.removeAll { $0 == suite } }
                            }
                        ))
                    }
                } else {
                    Text("Выбор шифров недоступен на iOS; система подбирает автоматически (вкл. AES-256-GCM)")
                        .font(.footnote).foregroundColor(.secondary)
                }
            }

            Section("Соединение") {
                Toggle("Ускорение по UDP", isOn: $udpEnabled)
                Stepper("MTU: \(mtu)", value: $mtu, in: 1280 ... 1500, step: 10)
            }

            Section("Трафик") {
                Toggle("Лимит трафика", isOn: $limitEnabled)
                if limitEnabled {
                    Stepper("Лимит: \(limitMB) МБ/день", value: $limitMB, in: 50 ... 10000, step: 50)
                }
                Stepper("Ротация: каждые \(rotationMinutes) мин", value: $rotationMinutes, in: 5 ... 240, step: 5)
            }

            Section {
                SecureField("QR-секрет (Base32)", text: $qrSecret)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Перенос MVC1")
            } footer: {
                Text("Тот же Base32-секрет, что в Android-сборке, — токены совместимы в обе стороны.")
            }
        }
        .navigationTitle("Настройки")
        .onAppear { load() }
        .onDisappear { save() }
    }

    private func suitesLabel(_ suite: String) -> String {
        switch suite {
        case "TLS_AES_256_GCM_SHA384": return "AES-256-GCM"
        case "TLS_CHACHA20_POLY1305_SHA256": return "ChaCha20-Poly1305"
        default: return "AES-128-GCM"
        }
    }

    private func load() {
        let store = AppModel.store
        sslVersion = store.sslVersion
        doSelectSuites = store.sslDoSelectSuites
        suites = store.sslSuites
        udpEnabled = store.udpAcceleration
        mtu = store.ethernetMTU
        limitEnabled = store.trafficLimitEnabled
        limitMB = store.trafficLimitMB
        rotationMinutes = store.rotationIntervalMinutes
        qrSecret = AppModel.qrSecret
    }

    private func save() {
        let store = AppModel.store
        store.sslVersion = sslVersion
        store.sslDoSelectSuites = doSelectSuites
        store.sslSuites = suites
        store.udpAcceleration = udpEnabled
        store.ethernetMTU = mtu
        store.trafficLimitEnabled = limitEnabled
        store.trafficLimitMB = limitMB
        store.rotationIntervalMinutes = rotationMinutes
        AppModel.sharedDefaults.set(qrSecret, forKey: prefServerSecret)
    }
}

// MARK: - QR export

struct QrExportView: View {
    let token: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            if let image = QrImage.generate(token) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .padding()
            } else {
                Text("Токен слишком длинный для одного QR")
                    .foregroundColor(.secondary)
            }
            Button("Закрыть") { dismiss() }
        }
        .padding()
    }
}

enum QrImage {
    // CIQRCodeGenerator caps at version 40 / level L ≈ 2953 bytes; stay safely below
    static let maxChars = 2300

    static func generate(_ string: String) -> UIImage? {
        guard string.utf8.count <= maxChars else { return nil }
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(string.utf8), forKey: "inputMessage")
        filter.setValue("L", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return nil }

        let scale = 12.0 / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
