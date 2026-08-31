import AVFoundation
import SwiftUI
import UIKit

struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode)
    }

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onCode = context.coordinator.handle
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerController, context: Context) {
        uiViewController.onCode = context.coordinator.handle
    }

    static func dismantleUIViewController(_ uiViewController: ScannerController, coordinator: Coordinator) {
        uiViewController.stopCapture()
    }

    final class Coordinator {
        let onCode: (String) -> Void
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }
        func handle(_ value: String) { onCode(value) }
    }
}

/// A presentation-scoped single-delivery gate. UIKit may retain a represented
/// controller when a SwiftUI sheet is dismissed and presented again, so this
/// state must be reset for every presentation rather than only in `viewDidLoad`.
final class QRScannerDeliveryGate {
    private(set) var delivered = false

    func beginPresentation() { delivered = false }

    func claimDelivery() -> Bool {
        guard !delivered else { return false }
        delivered = true
        return true
    }

    func claimDecodedValue(_ value: String?) -> String? {
        guard let value, claimDelivery() else { return nil }
        return value
    }
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "com.philcore.companion.qr-capture")
    private let deliveryGate = QRScannerDeliveryGate()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        deliveryGate.beginPresentation()
        sessionQueue.async { [weak self] in
            guard let self, !self.session.isRunning else { return }
            self.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        stopCapture()
    }

    func stopCapture() {
        sessionQueue.async { [weak self] in
            guard let self, self.session.isRunning else { return }
            self.session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        (view.layer.sublayers?.first as? AVCaptureVideoPreviewLayer)?.frame = view.bounds
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = deliveryGate.claimDecodedValue(object.stringValue) else { return }
        stopCapture()
        onCode?(value)
    }
}
