// GENERATED FILE - do not edit by hand.
// Generated from the ACS canonical token source: agentic-suite-site
// design/tokens.json (via design/generate.py -> design/out/acs_theme.dart).
// Committed copy for the ACT mobile app; re-copy after regenerating upstream.

import 'package:flutter/material.dart' show Color;

/// AgenticSuite canonical design tokens (`acs`).
///
/// Colors mirror `design/out/tokens.css` exactly; `*Soft` variants carry
/// the semantic color at 14% alpha for fills and pills on [bg].
class AcsTokens {
  AcsTokens._();

  // -- core ------------------------------------------------------------
  /// Canvas — the deep night background every dark surface sits on.
  static const Color bg = Color(0xFF0A0E14);

  /// Raised surface — cards, panels, console chrome sitting on bg.
  static const Color surface = Color(0xFF111721);

  /// Primary text on dark surfaces.
  static const Color ink = Color(0xFFE6EDF3);

  /// Secondary text — captions, de-emphasized labels, metadata.
  static const Color muted = Color(0xFF8B949E);

  /// Borders and dividers — the only elevation cue (see elevation.rule).
  static const Color hairline = Color(0xFF1E2733);

  /// Beacon amber — THE single brand accent. CTAs, brand mark, highlights. Never introduce a second accent.
  static const Color beacon = Color(0xFFF5A623);

  // -- semantic ramp (never convey status by color alone) --------------
  /// Clearance granted / connected / success.
  static const Color go = Color(0xFF5EC8A0);

  /// [go] at 14% alpha - fills/pills on [bg].
  static const Color goSoft = Color(0x245EC8A0);

  /// Pending / needs operator / medium risk. Intentionally identical to beacon — attention IS the brand's job.
  static const Color attention = Color(0xFFF5A623);

  /// [attention] at 14% alpha - fills/pills on [bg].
  static const Color attentionSoft = Color(0x24F5A623);

  /// High risk.
  static const Color warn = Color(0xFFE8892B);

  /// [warn] at 14% alpha - fills/pills on [bg].
  static const Color warnSoft = Color(0x24E8892B);

  /// Panic / deny / critical — reserved for these states only.
  static const Color alert = Color(0xFFFF5C5C);

  /// [alert] at 14% alpha - fills/pills on [bg].
  static const Color alertSoft = Color(0x24FF5C5C);

  // -- type ------------------------------------------------------------
  /// UI and body type.
  static const String fontSans = 'Inter';

  /// Labels, kickers, status readouts — set uppercase and tracked.
  static const String fontMono = 'IBM Plex Mono';

  /// Letter-spacing for uppercase mono labels/kickers.
  /// Em-relative: multiply by the current font size for letterSpacing.
  static const double trackingLabelEm = 0.14;

  // -- radius ----------------------------------------------------------
  /// Marketing surfaces — sharp corners, editorial.
  static const double radiusMarketing = 0.0;

  /// Allowance on app/touch surfaces (iOS panels, controls).
  static const double radiusApp = 8.0;

  // Elevation rule: Elevation is expressed with hairline borders only — no drop shadows.
}
