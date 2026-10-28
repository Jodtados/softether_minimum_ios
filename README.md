# SoftEther for iOS

Нативный iOS-клиент SoftEther VPN: Swift-порт протокольного слоя
[kittoku/mvc](https://github.com/kittoku/mvc) — функциональный клон Android-сборки
`softether_minimum` 0.8.x.

**Репозиторий личный/учебный. Пароли и QR-секреты в код не вшиты — всё вводится в приложении.**

## Возможности

- Подключение к SoftEther-серверу (TLS → HTTP-handshake → бинарный канал, DHCP и ARP
  внутри туннеля)
- Ускорение по UDP v2 (ChaCha20-Poly1305, NAT-T через порт 5004 и
  `nat-traversal.softether-network.net`)
- Закрепление сертификата сервера: pin-on-first-use (первое подключение запоминает
  лист-сертификат, дальше проверяется) или вставка PEM вручную
- Список серверов: ручной ввод, QR-сканер (камера/галерея), ссылки `vpn://`,
  `https://host/hub?user=&pass=&port=` и `host:port`
- Перенос настроек между Android ↔ iOS токенами **MVC1** (AES-256-GCM, байт-совместим;
  экспорт — в USER_BUILD-сборке)
- Лимит трафика (по умолчанию 500 МБ/день на сервер) с автопереключением на следующий
  сервер и ротацией по таймеру (30 мин), счётчики обнуляются в полночь
- Дефолты распознанных настроек: TLSv1.3, AES-256-GCM, UDP-ускорение, MTU 1500, порт 443

## Не-парity с Android (известные отличия)

- **Выбор шифр-сьютов косметический** — публичного API на iOS нет; Network.framework
  согласует с сервером сам (в набор по умолчанию входит AES-256-GCM). Настройка
  сохраняется и переносится, но не влияет на TLS.
- Нет автовосстановления соединения после потери сети (переподключение вручную).
- Сканер QR тестировался только на реальном устройстве.

## Сборка

### CI (GitHub Actions)

Репозиторий публичный → раннеры macOS бесплатны.

- **CI** (`ci.yml`, каждый push): юнит-тесты Core (`swift test`) — SHA-0, форматы
  PropertyPack/Units, парсер ссылок, кросс-платформенные векторы MVC1 из Android-тестов.
- **iOS unsigned IPA** (`ios-unsigned.yml`): Actions → *iOS unsigned IPA* → Run.
  Параметр `user_build` включает UI экспорта QR (`-DUSER_BUILD`). Артефакт
  `SoftEther-unsigned.ipa` — без подписи, для Sideloadly/Xcode.

### Локально (нужен macOS с Xcode 15+)

```sh
brew install xcodegen
xcodegen generate
open softether.xcodeproj   # выбрать команду/signing, Run на устройстве
```

Core можно проверять без Xcode-проекта: `swift test --package-path Core`.

## Установка IPA через Sideloadly

Unsigned-IPA не содержит подписи и entitlements — их добавляет Sideloadly при установке.

1. [Sideloadly](https://sideloadly.io), iPhone по USB, Apple ID (free).
2. Перетащить `SoftEther-unsigned.ipa`, открыть **Advanced options**.
3. Вставить в entitlements приложения И расширения (`SoftEtherNE.appex`):

```xml
<key>com.apple.security.application-groups</key>
<array><string>group.com.jodtados.softether</string></array>
<key>com.apple.developer.networking.networkextension</key>
<array><string>packet-tunnel-provider</string></array>
```

4. Start. Первый запуск: Настройки → VPN → разрешить конфигурацию (запрос появляется
   при первом «ПОДКЛЮЧИТЬСЯ»).
5. Через 7 дней подпись free-профиля истекает — переустановить тем же способом.

Через Xcode проще: открыть проект, выбрать свою команду в обоих таргетах, Run.

## Перенос серверов с Android (MVC1)

1. В Android-сборке: ⋮ → экспорт QR (или отдельные QR по серверу).
2. В iOS: Настройки → **QR-секрет (Base32)** — вставить тот же секрет, что вшит в
   Android-сборку (см. `local.properties` → `qrSecret` в Android-проекте).
3. Серверы → ⋮ → Сканировать QR. Токены совместимы в обе стороны (v1 — один сервер,
   v2 — пакетом; сертификат переносится внутри токена).

## Структура

```
Core/   SoftEtherCore (SwiftPM): протокол SoftEther, UDP-ускорение, MVC1, ServerStore
NE/     PacketTunnelProvider — NE-расширение, применяет настройки сети, лимит/ротация
App/    SwiftUI: список серверов, редактор, настройки, QR-сканер
```

## Лицензия

Apache-2.0 (унаследована от kittoku/mvc).
