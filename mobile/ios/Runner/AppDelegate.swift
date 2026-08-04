import Flutter
import UIKit
import UserNotifications

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  private var pushChannel: FlutterMethodChannel?
  private var latestApnsToken: String?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    registerForPushNotifications(application)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    if #available(iOS 13.0, *) {
      SecureEnclaveSigner.register(with: engineBridge.pluginRegistry)
    }
    if let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "ActPushToken") {
      let channel = FlutterMethodChannel(
        name: "act/push", binaryMessenger: registrar.messenger())
      channel.setMethodCallHandler { [weak self] call, result in
        if call.method == "requestToken" {
          result(self?.latestApnsToken)
        } else {
          result(FlutterMethodNotImplemented)
        }
      }
      pushChannel = channel
      // Deliver a token that arrived before the channel was created.
      if let token = latestApnsToken {
        channel.invokeMethod("onApnsToken", arguments: ["token": token])
      }
    }
  }

  private func registerForPushNotifications(_ application: UIApplication) {
    // `requestAuthorization` puts a SpringBoard alert in front of the app until
    // it is answered. Nothing inside the process can answer it — including an
    // integration test, which is *in* this process — so the app freezes and the
    // test hangs rather than failing. Reinstalling resets the authorization to
    // notDetermined, so this hits at unpredictable points in a suite run.
    //
    // The e2e driver sets SIMCTL_CHILD_ACT_SUPPRESS_PUSH_PROMPT=1, which
    // CoreSimulator forwards to the launched app as ACT_SUPPRESS_PUSH_PROMPT.
    // Nothing sets it outside that harness, so device and release behaviour are
    // unchanged. Losing push here costs nothing: APNs does not exist on the
    // Simulator at all.
    guard ProcessInfo.processInfo.environment["ACT_SUPPRESS_PUSH_PROMPT"] != "1"
    else {
      NSLog("ACT: push permission prompt suppressed (e2e harness)")
      return
    }
    UNUserNotificationCenter.current()
      .requestAuthorization(options: [.alert, .badge, .sound]) { granted, _ in
        guard granted else { return }
        DispatchQueue.main.async {
          application.registerForRemoteNotifications()
        }
      }
  }

  override func application(
    _ application: UIApplication,
    didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
  ) {
    let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
    latestApnsToken = hex
    pushChannel?.invokeMethod("onApnsToken", arguments: ["token": hex])
  }

  override func application(
    _ application: UIApplication,
    didFailToRegisterForRemoteNotificationsWithError error: Error
  ) {
    NSLog("ACT: APNs registration failed: \(error.localizedDescription)")
  }
}
