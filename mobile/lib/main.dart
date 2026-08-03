import 'src/bootstrap.dart';

/// Nothing may be awaited here beyond [bootstrapAndRun], which is budgeted so
/// the first frame can never be gated on push registration, a platform channel
/// or the network. See `src/bootstrap.dart` and `app_boot_test.dart`.
Future<void> main() => bootstrapAndRun();
