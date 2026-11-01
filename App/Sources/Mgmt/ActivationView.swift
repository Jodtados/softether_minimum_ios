// One-time activation gate screen (Android ActivationActivity): a 6-digit
// TOTP code from the build secret unlocks the install forever. A remote
// panic lock shows a dead end instead of the code field — no entry helps
// until the admin lifts it.

import SwiftUI

struct ActivationView: View {
    @ObservedObject var model: AppLockModel
    @State private var code = ""
    @State private var failedAttempts = 0
    @State private var cooldown = 0

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 56))
                .foregroundColor(.accentColor)
                .padding(.top, 48)

            Text("Активация")
                .font(.title2.bold())

            if model.panicLocked {
                Text("Приложение заблокировано")
                    .font(.headline)
                Text("Обратитесь к администратору.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            } else {
                SecureField("Код активации", text: $code)
                    .keyboardType(.numberPad)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .multilineTextAlignment(.center)
                    .font(.title3.monospacedDigit())
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 220)

                if cooldown > 0 {
                    Text("Слишком много попыток. Подождите \(cooldown) с")
                        .font(.footnote)
                        .foregroundColor(.red)
                } else if failedAttempts > 0 {
                    Text("Неверный код")
                        .font(.footnote)
                        .foregroundColor(.red)
                }

                Button("Активировать") {
                    tryActivate()
                }
                .buttonStyle(.borderedProminent)
                .disabled(code.count != 6 || cooldown > 0)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
        .onReceive(Timer.publish(every: 1, on: .main, in: .common).autoconnect()) { _ in
            // countdown straight from the lock state — it survives relaunches
            cooldown = AppLock.cooldownRemainingSeconds()
        }
    }

    private func tryActivate() {
        if AppLock.verify(code: code) {
            model.refresh()   // gateRequired flips → the real UI appears
        } else {
            failedAttempts += 1
            cooldown = AppLock.cooldownRemainingSeconds()
            code = ""
        }
    }
}
