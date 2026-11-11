// HassadNative — small native helpers for the Hassad Team iOS app.
//
// Inside an iOS app the web view can't download files (<a download>), open
// pop-up windows (window.open) or print (window.print). index.html detects the
// app (window.Capacitor) and calls these methods instead:
//
//   shareFile({ data, filename })  base64 file -> iOS share sheet
//                                  (Save to Files, Mail, WhatsApp, Print...)
//   printHtml({ html, name })      HTML document -> iOS print sheet
//   printPage({ name })            the current app screen -> iOS print sheet
//
// The iOS print sheet can also save as PDF (share button in its preview).
//
// This file lives in the CapApp-SPM package because `npx cap sync` only
// rewrites Package.swift there, never the Sources folder.
// HassadBridgeViewController registers the plugin; SceneDelegate uses it.

import Capacitor
import UIKit
import WebKit

@objc(HassadNativePlugin)
public class HassadNativePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "HassadNativePlugin"
    public let jsName = "HassadNative"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "shareFile", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "printHtml", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "printPage", returnType: CAPPluginReturnPromise)
    ]

    @objc func shareFile(_ call: CAPPluginCall) {
        guard let base64 = call.getString("data"),
              let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters) else {
            call.reject("No file data")
            return
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(Self.safeFileName(call.getString("filename") ?? "download"))
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            call.reject("Could not save the file: \(error.localizedDescription)")
            return
        }
        DispatchQueue.main.async {
            guard let presenter = self.presenter() else {
                call.reject("No screen to show the share sheet on")
                return
            }
            let sheet = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            if let popover = sheet.popoverPresentationController {
                popover.sourceView = presenter.view
                popover.sourceRect = CGRect(x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 1, height: 1)
                popover.permittedArrowDirections = []
            }
            sheet.completionWithItemsHandler = { _, completed, _, _ in
                call.resolve(["completed": completed])
            }
            presenter.present(sheet, animated: true)
        }
    }

    @objc func printHtml(_ call: CAPPluginCall) {
        let html = call.getString("html") ?? ""
        let name = call.getString("name") ?? "Hassad"
        DispatchQueue.main.async {
            self.presentPrint(name: name, formatter: UIMarkupTextPrintFormatter(markupText: html), call: call)
        }
    }

    @objc func printPage(_ call: CAPPluginCall) {
        let name = call.getString("name") ?? "Hassad"
        DispatchQueue.main.async {
            guard let webView = self.bridge?.webView else {
                call.reject("No web view")
                return
            }
            self.presentPrint(name: name, formatter: webView.viewPrintFormatter(), call: call)
        }
    }

    private func presentPrint(name: String, formatter: UIPrintFormatter, call: CAPPluginCall) {
        let info = UIPrintInfo(dictionary: nil)
        info.outputType = .general
        info.jobName = name
        let controller = UIPrintInteractionController.shared
        controller.printInfo = info
        controller.printFormatter = formatter
        _ = controller.present(animated: true) { _, completed, error in
            if let error = error {
                call.reject(error.localizedDescription)
            } else {
                call.resolve(["completed": completed])
            }
        }
    }

    private func presenter() -> UIViewController? {
        var top = bridge?.viewController
        while let presented = top?.presentedViewController {
            top = presented
        }
        return top
    }

    private static func safeFileName(_ name: String) -> String {
        let cleaned = name
            .components(separatedBy: CharacterSet(charactersIn: "/\\:?%*|\"<>"))
            .joined(separator: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? "download" : cleaned
    }
}

/// The app's root view controller: Capacitor's bridge plus the HassadNative plugin.
open class HassadBridgeViewController: CAPBridgeViewController {
    override open func capacitorDidLoad() {
        super.capacitorDidLoad()
        bridge?.registerPluginInstance(HassadNativePlugin())
    }
}
