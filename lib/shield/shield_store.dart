import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'shield_platform.dart';

/// UI state: the service status and the query log, polled while a screen
/// that shows them is open. The service keeps running when the app is closed.
class ShieldStore extends ChangeNotifier {
  ShieldStore({this.platform = const ShieldPlatform()});

  final ShieldPlatform platform;

  ShieldStatus? status;

  /// Queries seen while the app was open, newest first.
  final List<LogEntry> log = [];
  int _lastId = 0;

  /// Turning on (downloading lists, asking for the VPN) or updating lists.
  bool busy = false;

  Timer? _timer;
  int _listeners = 0;

  static const maxLog = 3000;

  /// Call from a screen's initState; pair with [unwatch].
  void watch() {
    _listeners++;
    _timer ??= Timer.periodic(const Duration(seconds: 2), (_) => refresh());
    refresh();
  }

  void unwatch() {
    _listeners--;
    if (_listeners <= 0) {
      _listeners = 0;
      _timer?.cancel();
      _timer = null;
    }
  }

  Future<void> refresh() async {
    try {
      status = await platform.status();
      var fresh = await platform.log(after: _lastId);
      if (fresh.isEmpty && _lastId > 0) {
        // The app process restarted: the service's ids start again from 1.
        final newest = await platform.log(limit: 1);
        if (newest.isNotEmpty && newest.first.id < _lastId) {
          log.clear();
          _lastId = 0;
          fresh = await platform.log();
        }
      }
      if (fresh.isNotEmpty) {
        _lastId = fresh.first.id;
        log.insertAll(0, fresh);
        if (log.length > maxLog) log.removeRange(maxLog, log.length);
      }
    } on PlatformException {
      // Keep the last known state.
    } on MissingPluginException {
      // Tests and non-Android hosts.
    }
    notifyListeners();
  }

  /// Turns protection on: downloads the lists the first time, then asks for
  /// the VPN permission. Returns an error text, or null when it worked.
  Future<String?> turnOn() async {
    busy = true;
    notifyListeners();
    try {
      if (!(status?.listsReady ?? false)) {
        final r = await platform.updateLists();
        if (r.domains == 0) {
          return 'Could not download the blocklists. Check your internet connection and try again.';
        }
      }
      final ok = await platform.start();
      if (!ok) return 'NetShield needs the VPN permission. It only uses it to filter DNS on this phone.';
      for (var i = 0; i < 10; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 300));
        await refresh();
        if (status?.running == true || status?.error != null) break;
      }
      return status?.error;
    } on PlatformException catch (e) {
      return e.message ?? 'Something went wrong.';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> turnOff() async {
    await platform.stop();
    await Future<void>.delayed(const Duration(milliseconds: 300));
    await refresh();
  }

  Future<UpdateResult> updateLists({bool force = false}) async {
    busy = true;
    notifyListeners();
    try {
      return await platform.updateLists(force: force);
    } finally {
      busy = false;
      await refresh();
    }
  }

  Future<void> clearLog() async {
    await platform.clearLog();
    log.clear();
    notifyListeners();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }
}
