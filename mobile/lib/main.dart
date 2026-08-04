import 'src/bootstrap.dart';
import 'src/error_net.dart';

/// Nothing may be awaited here beyond [bootstrapAndRun], which is budgeted so
/// the first frame can never be gated on push registration, a platform channel
/// or the network. See `src/bootstrap.dart` and `app_boot_test.dart`.
///
/// [installLastResortErrorNet] runs first and is not awaited: it only assigns
/// `PlatformDispatcher.onError`, so an error thrown during bootstrap itself is
/// already covered. It records and re-reports; it never swallows. See
/// `src/error_net.dart`.
Future<void> main() {
  installLastResortErrorNet();
  return bootstrapAndRun();
}
