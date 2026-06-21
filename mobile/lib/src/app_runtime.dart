import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'clearance/clearance_proof_verifier.dart' hide base64UrlDecodeNoPadding;
import 'clearance/tower_key.dart';
import 'security/push_token_channel.dart';
import 'security/secure_enclave_channel.dart';
import 'security/secure_enclave_signer.dart';
import 'api/gateway_api_client.dart';
import 'api/gateway_event_stream_client.dart';
import 'api/tui_stream_client.dart';
import 'config/gateway_config.dart';
import 'models/core_models.dart';
import 'repositories/agents_repository.dart';
import 'repositories/alpha_repository.dart';
import 'repositories/approval_responses_repository.dart';
import 'repositories/approvals_repository.dart';
import 'repositories/browser_assistance_repository.dart';
import 'repositories/dashboard_repository.dart';
import 'repositories/gateway_alpha_repository.dart';
import 'repositories/missions_repository.dart';
import 'repositories/mock_alpha_repository.dart';
import 'repositories/notifications_repository.dart';
import 'repositories/pairing_repository.dart';
import 'repositories/tua_repository.dart';
import 'repositories/tui_repository.dart';
import 'repositories/voice_repository.dart';
import 'security/device_request_signer.dart';
import 'security/secure_key_store.dart';

class HermesAppRuntime extends ChangeNotifier {
  HermesAppRuntime({
    required GatewayConfigStore configStore,
    required SecureKeyStore keyStore,
  })  : _configStore = configStore,
        _keyStore = keyStore;

  final GatewayConfigStore _configStore;
  final SecureKeyStore _keyStore;
  final SecureEnclaveChannel _enclave = const SecureEnclaveChannel();
  final PushTokenChannel _pushToken = const PushTokenChannel();
  String? _apnsToken;
  bool _pushHandlerInstalled = false;
  final ClearanceProofVerifier _proofVerifier = const ClearanceProofVerifier();
  final AlphaRepository _mockRepository = const MockAlphaRepository();

  GatewayConfig _config = GatewayConfig.loopback;
  String? _deviceId;
  String? _accessToken;
  String? _refreshToken;
  String? _privateKey;
  String? _publicKey;
  String? _keyAlgorithm;
  String? _towerPublicKeyB64;
  String _connectionStatus = 'Not checked';
  String _secureStorageStatus = 'Storage not checked';
  ClearanceKeyProtection _clearanceKeyProtection =
      ClearanceKeyProtection.unavailable;
  String _eventStreamStatus = 'Live stream idle';
  bool _eventStreamConnected = false;
  int _eventRevision = 0;
  String? _lastEventCursor;
  GatewayEvent? _lastEvent;
  final List<GatewayEvent> _recentEvents = [];
  StreamSubscription<GatewayEvent>? _eventSubscription;
  bool _refreshingToken = false;
  PairingSessionModel? _lastPairing;

  static Future<HermesAppRuntime> create() async {
    final preferences = await SharedPreferences.getInstance();
    final runtime = HermesAppRuntime(
      configStore: SharedPreferencesGatewayConfigStore(preferences),
      keyStore: PlatformAwareSecureKeyStore(preferences),
    );
    await runtime.initialize();
    return runtime;
  }

  GatewayConfig get config => _config;
  String? get deviceId => _deviceId;
  String? get accessToken => _accessToken;
  String get connectionStatus => _connectionStatus;
  String get secureStorageStatus => _secureStorageStatus;
  ClearanceKeyProtection get clearanceKeyProtection => _clearanceKeyProtection;
  String get eventStreamStatus => _eventStreamStatus;
  bool get eventStreamConnected => _eventStreamConnected;
  int get eventRevision => _eventRevision;
  GatewayEvent? get lastEvent => _lastEvent;
  List<GatewayEvent> get recentEvents => List.unmodifiable(_recentEvents);
  PairingSessionModel? get lastPairing => _lastPairing;
  bool get isPaired => _deviceId != null && _publicKey != null;
  String? get keyAlgorithm => _keyAlgorithm;
  bool get isEnclaveBacked => _keyAlgorithm == 'p256';
  bool get hasAccessToken => _accessToken != null && _refreshToken != null;
  String get dataModeLabel => isPaired ? 'Gateway data' : 'Mock alpha data';

  AlphaRepository get alphaRepository {
    if (!isPaired) {
      return _mockRepository;
    }
    final apiClient = _signedApiClient();
    return GatewayAlphaRepository(
      dashboardRepository: DashboardRepository(apiClient),
      agentsRepository: AgentsRepository(apiClient),
      approvalsRepository: ApprovalsRepository(apiClient),
      missionsRepository: MissionsRepository(apiClient),
      notificationsRepository: NotificationsRepository(apiClient),
      tuaRepository: TuaRepository(apiClient),
    );
  }

  TuiRepository? get tuiRepository {
    if (!isPaired) {
      return null;
    }
    return TuiRepository(_signedApiClient());
  }

  TuaRepository? get tuaRepository {
    if (!isPaired) {
      return null;
    }
    return TuaRepository(_signedApiClient());
  }

  BrowserAssistanceRepository? get browserAssistanceRepository {
    if (!isPaired) {
      return null;
    }
    return BrowserAssistanceRepository(_signedApiClient());
  }

  ApprovalResponsesRepository? get approvalResponsesRepository {
    if (!isPaired) {
      return null;
    }
    return ApprovalResponsesRepository(_signedApiClient());
  }

  VoiceRepository? get voiceRepository {
    if (!isPaired) {
      return null;
    }
    return VoiceRepository(_signedApiClient());
  }

  TuiStreamClient? get tuiStreamClient {
    final token = _accessToken;
    if (!isPaired || token == null || token.isEmpty) {
      return null;
    }
    return TuiStreamClient(config: _config);
  }

  Future<void> initialize() async {
    _installPushHandler();
    _config = await _configStore.read();
    _deviceId = await _keyStore.readDeviceId();
    _accessToken = await _keyStore.readAccessToken();
    _refreshToken = await _keyStore.readRefreshToken();
    _privateKey = await _keyStore.readDevicePrivateKey();
    _publicKey = await _keyStore.readDevicePublicKey();
    _keyAlgorithm = await _keyStore.readDeviceKeyAlgorithm();
    _towerPublicKeyB64 = await _keyStore.readTowerPublicKey();
    _secureStorageStatus = await _keyStore.storageWarning();
    _clearanceKeyProtection = await _resolveProtection();
    if (!await _storedDeviceKeyIsValid()) {
      await _keyStore.clear();
      _deviceId = null;
      _accessToken = null;
      _refreshToken = null;
      _privateKey = null;
      _publicKey = null;
      _connectionStatus = 'Pairing reset: stored device key mismatch';
    }
    if (isPaired && _accessToken != null) {
      await _startEventStream();
      await _registerPushToken();
    }
    notifyListeners();
  }

  /// Wire the native APNs token bridge once; uploads whenever a token arrives.
  void _installPushHandler() {
    if (_pushHandlerInstalled) {
      return;
    }
    _pushHandlerInstalled = true;
    _pushToken.onToken((token) {
      _apnsToken = token;
      unawaited(_uploadPushToken());
    });
  }

  /// Pull the latest APNs token from native and upload it to the gateway for
  /// this paired device. Best-effort; failures never block the app.
  Future<void> _registerPushToken() async {
    _apnsToken ??= await _pushToken.requestToken();
    await _uploadPushToken();
  }

  Future<void> _uploadPushToken() async {
    final token = _apnsToken;
    if (token == null || token.isEmpty || !isPaired || _accessToken == null) {
      return;
    }
    try {
      await _signedApiClient().postJson(
        '/devices/me/push-token',
        body: {'push_token': token},
      );
    } on Object {
      // best-effort push registration
    }
  }

  Future<void> saveGatewayBaseUrl(String value) async {
    _config = GatewayConfig.fromInput(value);
    await _configStore.save(_config);
    _connectionStatus = 'Gateway URL saved';
    if (isPaired && _accessToken != null) {
      await _restartEventStream();
    }
    notifyListeners();
  }

  Future<void> checkHealth() async {
    try {
      final response =
          await _unsignedApiClient().getJson('/health', signed: false);
      _connectionStatus =
          'Connected: ${response['node_id']} ${response['status']}';
    } on Object catch (error) {
      _connectionStatus = 'Connection failed: $error';
    }
    notifyListeners();
  }

  Future<PairingSessionModel> startPairing() async {
    final session = await PairingRepository(_unsignedApiClient()).startPairing(
      displayName: 'ACT Operator Alpha',
    );
    _lastPairing = session;
    _connectionStatus = 'Pairing started';
    notifyListeners();
    return session;
  }

  Future<void> completePairing(PairingSessionModel session) async {
    final towerKeyB64 =
        base64UrlNoPadding(await deriveTowerPublicKey(session.nodeFingerprint));
    final completion = await (await _enclave.isAvailable()
        ? _completePairingWithEnclave(session, towerKeyB64)
        : _completePairingWithSoftwareKey(session, towerKeyB64));

    await _keyStore.saveDeviceSession(
      deviceId: completion.deviceId,
      accessToken: completion.accessToken,
      refreshToken: completion.refreshToken,
    );
    _deviceId = completion.deviceId;
    _accessToken = completion.accessToken;
    _refreshToken = completion.refreshToken;
    _towerPublicKeyB64 = towerKeyB64;
    _clearanceKeyProtection = await _resolveProtection();
    _lastPairing = null;
    _connectionStatus = 'Paired with ${completion.node.displayName}';
    await _restartEventStream();
    await _registerPushToken();
    notifyListeners();
  }

  /// Secure-Enclave path: generate a non-exportable P-256 key, prove key
  /// possession by signing the pairing challenge inside the enclave, and enrol as
  /// a `p256` mobile_signed device. No private key is ever stored by the app.
  Future<PairingCompletionModel> _completePairingWithEnclave(
    PairingSessionModel session,
    String towerKeyB64,
  ) async {
    final key = await _enclave.generateKey(requireBiometry: true);
    final possessionProof = await _enclave.sign(
      data: Uint8List.fromList(utf8.encode(session.challenge)),
      reason: 'Pair this device with your control tower',
    );
    final completion =
        await PairingRepository(_unsignedApiClient()).completePairing(
      pairing: session,
      devicePublicKey: key.publicKeyBase64,
      deviceKeyAlgorithm: key.algorithm,
      devicePossessionProof: possessionProof,
    );
    await _keyStore.saveDeviceEnrollment(
      publicKey: key.publicKeyBase64,
      algorithm: key.algorithm,
      towerPublicKey: towerKeyB64,
    );
    _privateKey = null;
    _publicKey = key.publicKeyBase64;
    _keyAlgorithm = key.algorithm;
    return completion;
  }

  /// Legacy/dev (web) path: software Ed25519 key. Clearly non-hardware-backed.
  Future<PairingCompletionModel> _completePairingWithSoftwareKey(
    PairingSessionModel session,
    String towerKeyB64,
  ) async {
    final keyPair = await DeviceKeyPair.generate();
    final completion =
        await PairingRepository(_unsignedApiClient()).completePairing(
      pairing: session,
      devicePublicKey: keyPair.publicKeyBase64,
    );
    await _keyStore.saveDeviceKeyPair(
      privateKey: keyPair.privateKeyBase64,
      publicKey: keyPair.publicKeyBase64,
    );
    _privateKey = keyPair.privateKeyBase64;
    _publicKey = keyPair.publicKeyBase64;
    _keyAlgorithm = 'ed25519';
    return completion;
  }

  /// Resolve the honest protection record: native-sourced on iOS (enclave or
  /// software-dev), key-store-sourced otherwise.
  Future<ClearanceKeyProtection> _resolveProtection() async {
    final status = await _enclave.status();
    if (status != null && (_keyAlgorithm == 'p256' || status.hasKey)) {
      return status.toProtection();
    }
    return _keyStore.clearanceKeyProtection();
  }

  /// Verify a clearance object's published proof against the pinned tower key,
  /// fail-closed. Returns a non-verified result if no tower key is pinned.
  Future<ProofVerification> verifyClearanceProof(
    Map<String, dynamic> clearance, {
    String? expectedCapability,
  }) async {
    final towerKeyB64 = _towerPublicKeyB64;
    if (towerKeyB64 == null) {
      return ProofVerification.fail('tower_key_unpinned');
    }
    return _proofVerifier.verifyClearance(
      clearance: clearance,
      towerPublicKey: base64UrlDecodeNoPadding(towerKeyB64),
      expectedCapability: expectedCapability,
    );
  }

  Future<void> clearPairing() async {
    await _stopEventStream();
    await _enclave.clearKey();
    await _keyStore.clear();
    _deviceId = null;
    _accessToken = null;
    _refreshToken = null;
    _privateKey = null;
    _publicKey = null;
    _keyAlgorithm = null;
    _towerPublicKeyB64 = null;
    _lastPairing = null;
    _connectionStatus = 'Pairing cleared';
    _clearanceKeyProtection = await _resolveProtection();
    _eventStreamStatus = 'Live stream idle';
    _eventStreamConnected = false;
    _eventRevision += 1;
    _lastEventCursor = null;
    _lastEvent = null;
    _recentEvents.clear();
    notifyListeners();
  }

  Future<void> refreshLiveData() async {
    _eventRevision += 1;
    notifyListeners();
  }

  GatewayApiClient _unsignedApiClient() {
    return GatewayApiClient(
      config: _config,
      signer: const UnavailableDeviceRequestSigner(),
    );
  }

  GatewayApiClient _signedApiClient() {
    final deviceId = _deviceId;
    if (deviceId == null) {
      return _unsignedApiClient();
    }
    if (_keyAlgorithm == 'p256') {
      return GatewayApiClient(
        config: _config,
        signer: SecureEnclaveDeviceRequestSigner(
          deviceId: deviceId,
          channel: _enclave,
          protection: _clearanceKeyProtection,
        ),
        accessToken: _accessToken,
      );
    }
    final privateKey = _privateKey;
    final publicKey = _publicKey;
    if (privateKey == null || publicKey == null) {
      return _unsignedApiClient();
    }
    return GatewayApiClient(
      config: _config,
      signer: Ed25519DeviceRequestSigner(
        deviceId: deviceId,
        keyPair: DeviceKeyPair.fromBase64(
          privateKey: privateKey,
          publicKey: publicKey,
        ),
      ),
      accessToken: _accessToken,
    );
  }

  Future<bool> _storedDeviceKeyIsValid() async {
    final publicKey = _publicKey;
    if (publicKey == null && _privateKey == null && _deviceId == null) {
      return true; // fresh, never paired
    }
    if (_deviceId == null || publicKey == null) {
      return false;
    }
    if (_keyAlgorithm == 'p256') {
      // Non-exportable enclave key: validate by presence only — signing here
      // would force a biometric prompt at launch.
      final status = await _enclave.status();
      return status?.hasKey ?? false;
    }
    final privateKey = _privateKey;
    if (privateKey == null) {
      return false;
    }
    try {
      return DeviceKeyPair.fromBase64(
        privateKey: privateKey,
        publicKey: publicKey,
      ).validatesPair();
    } on Object {
      return false;
    }
  }

  @override
  void dispose() {
    _eventSubscription?.cancel();
    super.dispose();
  }

  Future<void> _startEventStream() async {
    final token = _accessToken;
    if (token == null || token.isEmpty) {
      _eventStreamStatus = 'Pairing token unavailable';
      _eventStreamConnected = false;
      return;
    }
    await _eventSubscription?.cancel();
    _eventStreamStatus = 'Live stream connecting';
    _eventStreamConnected = false;
    _eventSubscription = GatewayEventStreamClient(
      config: _config,
      accessToken: token,
      onConnectError: _onStreamConnectError,
    ).connect(after: _lastEventCursor).listen(
      _handleGatewayEvent,
      onError: (Object error) {
        _eventStreamStatus = 'Live stream error: $error';
        _eventStreamConnected = false;
        notifyListeners();
      },
      onDone: () {
        _eventStreamStatus = 'Live stream disconnected';
        _eventStreamConnected = false;
        notifyListeners();
      },
    );
  }

  Future<void> _restartEventStream() async {
    await _stopEventStream();
    await _startEventStream();
  }

  /// The paired-device access token has a short TTL; when it expires the event
  /// stream gets HTTP 403 and stops delivering. Detect that and refresh the
  /// token (signed) then reconnect, instead of looping forever on a dead token.
  void _onStreamConnectError(Object error) {
    final text = error.toString().toLowerCase();
    final looksLikeAuth = text.contains('403') ||
        text.contains('401') ||
        text.contains('forbidden') ||
        text.contains('unauthor');
    if (looksLikeAuth) {
      unawaited(_refreshTokenAndRestartStream());
    }
  }

  Future<void> _refreshTokenAndRestartStream() async {
    if (_refreshingToken) {
      return;
    }
    _refreshingToken = true;
    try {
      _eventStreamStatus = 'Live stream re-authenticating';
      notifyListeners();
      if (await refreshAccessToken()) {
        await _restartEventStream();
      }
    } finally {
      _refreshingToken = false;
    }
  }

  /// Exchange the refresh token for a fresh access token (signed request).
  /// Returns true on success. Persists the rotated tokens.
  Future<bool> refreshAccessToken() async {
    final refresh = _refreshToken;
    final deviceId = _deviceId;
    if (refresh == null || deviceId == null) {
      return false;
    }
    try {
      final response = await _signedApiClient().postJson(
        '/auth/token/refresh',
        body: {'refresh_token': refresh},
      );
      final newAccess = response['access_token'] as String?;
      final newRefresh = response['refresh_token'] as String?;
      if (newAccess == null || newRefresh == null) {
        return false;
      }
      _accessToken = newAccess;
      _refreshToken = newRefresh;
      await _keyStore.saveDeviceSession(
        deviceId: deviceId,
        accessToken: newAccess,
        refreshToken: newRefresh,
      );
      return true;
    } on Object {
      return false;
    }
  }

  Future<void> _stopEventStream() async {
    final subscription = _eventSubscription;
    _eventSubscription = null;
    await subscription?.cancel();
  }

  void _handleGatewayEvent(GatewayEvent event) {
    _lastEvent = event;
    _lastEventCursor = event.cursor;
    _recentEvents.insert(0, event);
    if (_recentEvents.length > 30) {
      _recentEvents.removeRange(30, _recentEvents.length);
    }
    _eventStreamConnected = true;
    _eventStreamStatus = 'Live: ${event.type}';
    _eventRevision += 1;
    notifyListeners();
  }
}

class HermesRuntimeScope extends InheritedNotifier<HermesAppRuntime> {
  const HermesRuntimeScope({
    required HermesAppRuntime runtime,
    required super.child,
    super.key,
  }) : super(notifier: runtime);

  static HermesAppRuntime of(BuildContext context) {
    final scope =
        context.dependOnInheritedWidgetOfExactType<HermesRuntimeScope>();
    if (scope == null || scope.notifier == null) {
      throw StateError('Hermes runtime scope is not available.');
    }
    return scope.notifier!;
  }
}
