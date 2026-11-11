import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';

/// An installed app's icon, loaded once and kept in memory. System processes
/// and unknown senders get a plain icon box.
class AppIcon extends StatelessWidget {
  const AppIcon(this.app, {super.key, this.size = 32, this.platform = const ShieldPlatform()});

  final String app;
  final double size;
  final ShieldPlatform platform;

  static final Map<String, Future<Uint8List?>> _cache = {};

  @override
  Widget build(BuildContext context) {
    if (app == 'unknown' || app.startsWith('uid:')) {
      return UiIconBox(
        app == 'unknown' ? Icons.help_outline_rounded : Icons.memory_rounded,
        status: UiStatus.neutral,
        size: size,
      );
    }
    final future = _cache.putIfAbsent(app, () => platform.appIcon(app).catchError((Object _) => null));
    return FutureBuilder<Uint8List?>(
      future: future,
      builder: (context, snap) {
        final bytes = snap.data;
        if (bytes == null) return UiIconBox(Icons.apps_rounded, status: UiStatus.neutral, size: size);
        return ClipRRect(
          borderRadius: BorderRadius.circular(size * 0.22),
          child: Image.memory(bytes, width: size, height: size, gaplessPlayback: true),
        );
      },
    );
  }
}
