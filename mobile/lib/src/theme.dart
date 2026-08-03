import 'package:flutter/material.dart';

import 'acs_tokens.dart';

/// ACS canonical dark theme for the ACT operator app.
///
/// Colors and type come from [AcsTokens] (the agenticsuite.work anchor):
/// beacon amber is THE accent and carries approval/attention surfaces,
/// `go` green means connected/success, `alert` red is reserved for
/// panic/deny/critical. Inter for UI, IBM Plex Mono for status/ids.
ThemeData hermesTheme() {
  const background = AcsTokens.bg;
  const surface = AcsTokens.surface;
  // Derived raised-input tone: one step from surface toward hairline.
  const surfaceBright = Color(0xFF18202C);
  const text = AcsTokens.ink;
  const muted = AcsTokens.muted;

  return ThemeData(
    colorScheme: const ColorScheme.dark(
      primary: AcsTokens.beacon,
      onPrimary: background,
      secondary: AcsTokens.attention,
      onSecondary: background,
      tertiary: AcsTokens.go,
      onTertiary: background,
      surface: surface,
      surfaceContainerHighest: surfaceBright,
      onSurface: text,
      outline: muted,
      outlineVariant: AcsTokens.hairline,
      error: AcsTokens.alert,
      onError: background,
    ),
    scaffoldBackgroundColor: background,
    fontFamily: AcsTokens.fontSans,
    appBarTheme: const AppBarTheme(
      centerTitle: false,
      elevation: 0,
      backgroundColor: background,
      foregroundColor: text,
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: surface,
      indicatorColor: AcsTokens.beacon.withValues(alpha: 0.14),
      labelTextStyle: WidgetStateProperty.resolveWith(
        (_) => const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
      ),
    ),
    listTileTheme: const ListTileThemeData(
      contentPadding: EdgeInsets.symmetric(horizontal: 20, vertical: 4),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: surfaceBright,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: BorderSide.none,
      ),
      hintStyle: const TextStyle(color: muted),
    ),
    useMaterial3: true,
  );
}
