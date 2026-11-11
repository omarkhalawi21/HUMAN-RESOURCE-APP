// HassadNative — small native helpers for the Hassad Team iOS app.
//
// Inside an iOS app the web view can't download files (<a download>), open
// pop-up windows (window.open) or print (window.print). index.html detects the
// app (window.Capacitor) and calls these methods instead:
//
//   shareFile({ data, filename })  base64 file -> iOS share sheet
//                                  (Save to Files, Mail, WhatsApp, Print...)
//   printHtml({ html, name })      HTML document -> rendered in a hidden
//                                  web view -> iOS print sheet
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

    // The document is rendered in a hidden WKWebView first and printed from
    // that view. UIMarkupTextPrintFormatter was tried first, but it supports
    // only basic HTML, can't load the documents' images and CSS, and gave up
    // (completed:false, NSURLErrorUnsupportedURL -1002) on every print.
    private var htmlPrintJob: HtmlPrintJob?

    @objc func printHtml(_ call: CAPPluginCall) {
        let html = call.getString("html") ?? ""
        let name = call.getString("name") ?? "Hassad"
        DispatchQueue.main.async {
            guard let host = self.bridge?.viewController?.view else {
                call.reject("No screen to print from")
                return
            }
            // The app's own files (e.g. logo.png) live in the bundled "public"
            // folder. Point both relative and capacitor://localhost/ links there.
            let base = Bundle.main.url(forResource: "public", withExtension: nil)
            var markup = html
            if let base = base {
                markup = markup.replacingOccurrences(of: "capacitor://localhost/", with: base.absoluteString)
            }
            self.htmlPrintJob?.cleanup()
            let job = HtmlPrintJob(html: markup, baseURL: base, host: host) { [weak self] webView in
                guard let self = self else { return }
                guard let webView = webView else {
                    self.htmlPrintJob?.cleanup()
                    self.htmlPrintJob = nil
                    call.reject("Could not prepare the document for printing")
                    return
                }
                self.presentPrint(name: name, formatter: webView.viewPrintFormatter(), call: call) {
                    self.htmlPrintJob?.cleanup()
                    self.htmlPrintJob = nil
                }
            }
            self.htmlPrintJob = job
            job.start()
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

    private func presentPrint(name: String, formatter: UIPrintFormatter, call: CAPPluginCall,
                              finished: (() -> Void)? = nil) {
        let info = UIPrintInfo(dictionary: nil)
        info.outputType = .general
        info.jobName = name
        let controller = UIPrintInteractionController.shared
        controller.printInfo = info
        controller.printFormatter = formatter
        let shown = controller.present(animated: true) { _, completed, error in
            finished?()
            if let error = error {
                call.reject(error.localizedDescription)
            } else {
                call.resolve(["completed": completed])
            }
        }
        if !shown {
            // e.g. the print sheet is already open from a double tap.
            finished?()
            call.reject("The print sheet is already open")
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

/// Loads an HTML string into an invisible WKWebView and reports when it has
/// finished loading, so the page can be printed with its full CSS and images.
final class HtmlPrintJob: NSObject, WKNavigationDelegate {
    private let webView: WKWebView
    private let html: String
    private let baseURL: URL?
    private let onReady: (WKWebView?) -> Void
    private var reported = false

    init(html: String, baseURL: URL?, host: UIView, onReady: @escaping (WKWebView?) -> Void) {
        self.html = html
        self.baseURL = baseURL
        self.onReady = onReady
        // Roughly A4 at 96 dpi; the print formatter re-flows it to the paper size.
        webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 794, height: 1123))
        super.init()
        webView.navigationDelegate = self
        webView.isUserInteractionEnabled = false
        webView.alpha = 0.01
        host.insertSubview(webView, at: 0)
    }

    func start() {
        webView.loadHTMLString(html, baseURL: baseURL)
    }

    func cleanup() {
        webView.navigationDelegate = nil
        webView.removeFromSuperview()
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // A short pause lets images and web fonts finish painting.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { self.report(webView) }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        report(nil)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        report(nil)
    }

    private func report(_ view: WKWebView?) {
        guard !reported else { return }
        reported = true
        onReady(view)
    }
}

/// The app's root view controller: Capacitor's bridge plus the HassadNative plugin.
open class HassadBridgeViewController: CAPBridgeViewController {
    override open func capacitorDidLoad() {
        super.capacitorDidLoad()
        bridge?.registerPluginInstance(HassadNativePlugin())
    }
}
