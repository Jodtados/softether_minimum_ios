// QR scanner: camera + photo import (ScannerFragment of softether_minimum).

import SwiftUI
import AVFoundation
import CoreImage
import PhotosUI

struct ScannerView: View {
    let onToken: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var cameraAvailable = true
    @State private var showPhotoPicker = false
    @State private var failureText: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                if cameraAvailable {
                    CameraScannerView(onToken: { token in
                        onToken(token)
                    })
                    .overlay {
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color.accentColor, lineWidth: 2)
                            .padding(40)
                    }
                } else {
                    Image(systemName: "camera.on.rectangle")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("Камера недоступна")
                        .foregroundColor(.secondary)
                }

                if let failureText {
                    Text(failureText)
                        .font(.footnote)
                        .foregroundColor(.red)
                }

                Button {
                    showPhotoPicker = true
                } label: {
                    Label("Выбрать из галереи", systemImage: "photo")
                }
                .buttonStyle(.bordered)
            }
            .padding()
            .navigationTitle("Сканирование QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Закрыть") { dismiss() }
                }
            }
            .sheet(isPresented: $showPhotoPicker) {
                PhotoQrPicker { token in
                    if let token {
                        onToken(token)
                    } else {
                        failureText = "QR на фото не найден"
                    }
                }
            }
            .onAppear {
                switch AVCaptureDevice.authorizationStatus(for: .video) {
                case .authorized: cameraAvailable = true
                case .notDetermined:
                    AVCaptureDevice.requestAccess(for: .video) { granted in
                        DispatchQueue.main.async { cameraAvailable = granted }
                    }
                default: cameraAvailable = false
                }
            }
        }
    }
}

// MARK: - live camera

struct CameraScannerView: UIViewRepresentable {
    let onToken: (String) -> Void

    func makeUIView(context: Context) -> UIView {
        let view = PreviewUIView()
        view.onToken = onToken
        view.session = context.coordinator.session
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onToken: onToken)
    }

    final class PreviewUIView: UIView {
        var onToken: ((String) -> Void)?
        var session: AVCaptureSession? {
            didSet {
                guard let session else { return }
                (layer as? AVCaptureVideoPreviewLayer)?.session = session
            }
        }

        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let session = AVCaptureSession()
        private let onToken: (String) -> Void
        private var delivered = false

        init(onToken: @escaping (String) -> Void) {
            self.onToken = onToken
            super.init()

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                guard let device = AVCaptureDevice.default(for: .video),
                      let input = try? AVCaptureDeviceInput(device: device),
                      self.session.canAddInput(input)
                else { return }

                self.session.beginConfiguration()
                self.session.addInput(input)

                let output = AVCaptureMetadataOutput()
                if self.session.canAddOutput(output) {
                    self.session.addOutput(output)
                    output.metadataObjectTypes = [.qr]
                    output.setMetadataObjectsDelegate(self, queue: .main)
                }
                self.session.commitConfiguration()
                self.session.startRunning()
            }
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            guard !delivered else { return }
            guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  object.type == .qr,
                  let value = object.stringValue
            else { return }

            delivered = true
            onToken(value)
        }

        deinit {
            session.stopRunning()
        }
    }
}

// MARK: - photo import

struct PhotoQrPicker: UIViewControllerRepresentable {
    let onComplete: (String?) -> Void

    func makeUIViewController(context: Context) -> PHPickerViewController {
        var config = PHPickerConfiguration()
        config.filter = .images
        config.selectionLimit = 1
        let picker = PHPickerViewController(configuration: config)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ uiViewController: PHPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onComplete: onComplete)
    }

    final class Coordinator: NSObject, PHPickerViewControllerDelegate {
        private let onComplete: (String?) -> Void

        init(onComplete: @escaping (String?) -> Void) {
            self.onComplete = onComplete
        }

        func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
            guard let provider = results.first?.itemProvider,
                  provider.canLoadObject(ofClass: UIImage.self)
            else {
                onComplete(nil)
                return
            }

            provider.loadObject(ofClass: UIImage.self) { [onComplete] object, _ in
                DispatchQueue.main.async {
                    guard let image = object as? UIImage else {
                        onComplete(nil)
                        return
                    }
                    onComplete(Self.detectQr(in: image))
                }
            }
        }

        static func detectQr(in image: UIImage) -> String? {
            guard let ciImage = CIImage(image: image) else { return nil }
            let options = [CIDetectorAccuracy: CIDetectorAccuracyHigh, CIDetectorAspectRatio: 1.0]
            guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: options)
            else { return nil }

            var features = detector.features(in: ciImage, options: options)
            if features.isEmpty {
                let rotated = ciImage.oriented(.right)
                features = detector.features(in: rotated, options: options)
            }
            return (features.first as? CIQRCodeFeature)?.messageString
        }
    }
}
