import 'package:flutter/services.dart';

/// Why a query got its answer. The numbers match `Verdict` in Filter.kt.
enum Verdict {
  allowed('Allowed'),
  blockedList('Blocked by a list'),
  blockedRule('Blocked by your rule'),
  blockedAppRule('Blocked for this app'),
  blockedCname('Blocked: hidden tracker'),
  blockedUpstream('Blocked by the DNS server'),
  allowedRule('Allowed by your rule'),
  error('DNS server not reachable');

  const Verdict(this.label);
  final String label;

  static Verdict of(int i) => i >= 0 && i < values.length ? values[i] : allowed;

  bool get blocked => index >= blockedList.index && index <= blockedUpstream.index;
}

/// The DNS server allowed queries go to.
enum Upstream {
  adguard('adguard', 'AdGuard DNS', 'Blocks ads too: a second layer behind your lists.'),
  cloudflare('cloudflare', 'Cloudflare', 'Fastest in most places. No filtering.'),
  quad9('quad9', 'Quad9', 'Blocks known malware domains. Swiss privacy law.'),
  google('google', 'Google', 'Very reliable. No filtering.');

  const Upstream(this.key, this.label, this.description);
  final String key;
  final String label;
  final String description;

  static Upstream of(String? key) => values.firstWhere((u) => u.key == key, orElse: () => adguard);
}

class ShieldStatus {
  const ShieldStatus({
    required this.running,
    required this.enabled,
    required this.error,
    required this.listsReady,
    required this.domains,
    required this.listsUpdatedAt,
    required this.updating,
    required this.upstream,
    required this.interceptDns,
    required this.privateDnsMode,
    required this.privateDnsHost,
    required this.perApp,
    required this.notifications,
    required this.today,
    required this.todayBlocked,
  });

  factory ShieldStatus.fromMap(Map<Object?, Object?> m) => ShieldStatus(
    running: m['running'] as bool? ?? false,
    enabled: m['enabled'] as bool? ?? false,
    error: m['error'] as String?,
    listsReady: m['listsReady'] as bool? ?? false,
    domains: (m['domains'] as num?)?.toInt() ?? 0,
    listsUpdatedAt: _date(m['listsUpdatedAt']),
    updating: m['updating'] as String?,
    upstream: Upstream.of(m['upstream'] as String?),
    interceptDns: m['interceptDns'] as bool? ?? true,
    privateDnsMode: m['privateDnsMode'] as String?,
    privateDnsHost: m['privateDnsHost'] as String?,
    perApp: m['perApp'] as bool? ?? false,
    notifications: m['notifications'] as bool? ?? true,
    today: (m['today'] as num?)?.toInt() ?? 0,
    todayBlocked: (m['todayBlocked'] as num?)?.toInt() ?? 0,
  );

  final bool running;
  final bool enabled;
  final String? error;
  final bool listsReady;
  final int domains;
  final DateTime? listsUpdatedAt;

  /// What a list update is doing, or null when idle.
  final String? updating;
  final Upstream upstream;
  final bool interceptDns;

  /// Android's Private DNS setting: "off", "opportunistic" (automatic) or "hostname".
  final String? privateDnsMode;
  final String? privateDnsHost;

  /// Android 10+ can tell which app sent each query.
  final bool perApp;
  final bool notifications;
  final int today;
  final int todayBlocked;

  /// Private DNS with a named provider sends DNS around the VPN: nothing gets filtered.
  bool get privateDnsBypass => privateDnsMode == 'hostname';

  double get blockedShare => today == 0 ? 0 : todayBlocked / today;

  static DateTime? _date(Object? v) {
    final ms = (v as num?)?.toInt() ?? 0;
    return ms <= 0 ? null : DateTime.fromMillisecondsSinceEpoch(ms);
  }
}

class LogEntry {
  const LogEntry({
    required this.id,
    required this.time,
    required this.domain,
    required this.type,
    required this.app,
    required this.label,
    required this.verdict,
    required this.ms,
    this.detail,
  });

  factory LogEntry.fromMap(Map<Object?, Object?> m) => LogEntry(
    id: (m['id'] as num).toInt(),
    time: DateTime.fromMillisecondsSinceEpoch((m['time'] as num).toInt()),
    domain: m['domain'] as String,
    type: (m['type'] as num?)?.toInt() ?? 0,
    app: m['app'] as String? ?? 'unknown',
    label: m['label'] as String? ?? 'Unknown app',
    verdict: Verdict.of((m['verdict'] as num?)?.toInt() ?? 0),
    ms: (m['ms'] as num?)?.toInt() ?? 0,
    detail: m['detail'] as String?,
  );

  final int id;
  final DateTime time;
  final String domain;
  final int type;

  /// Package name, "uid:N" for a system process, or "unknown".
  final String app;
  final String label;
  final Verdict verdict;
  final int ms;

  /// First address, the hidden tracker name, or the error.
  final String? detail;

  /// A real installed app (rules can be made just for it).
  bool get isPackage => app != 'unknown' && !app.startsWith('uid:');

  String get typeName => switch (type) {
    1 => 'A',
    5 => 'CNAME',
    12 => 'PTR',
    15 => 'MX',
    16 => 'TXT',
    28 => 'AAAA',
    33 => 'SRV',
    64 => 'SVCB',
    65 => 'HTTPS',
    _ => 'TYPE$type',
  };
}

class ListInfo {
  const ListInfo({
    required this.id,
    required this.name,
    required this.description,
    required this.group,
    required this.recommended,
    required this.enabled,
    required this.count,
  });

  factory ListInfo.fromMap(Map<Object?, Object?> m) => ListInfo(
    id: m['id'] as String,
    name: m['name'] as String,
    description: m['description'] as String? ?? '',
    group: m['group'] as String? ?? 'Other',
    recommended: m['recommended'] as bool? ?? false,
    enabled: m['enabled'] as bool? ?? false,
    count: (m['count'] as num?)?.toInt() ?? 0,
  );

  final String id;
  final String name;
  final String description;
  final String group;
  final bool recommended;
  final bool enabled;
  final int count;
}

class AppStat {
  const AppStat({required this.app, required this.label, required this.queries, required this.blocked, required this.bypass});

  factory AppStat.fromMap(Map<Object?, Object?> m) => AppStat(
    app: m['app'] as String,
    label: m['label'] as String? ?? m['app'] as String,
    queries: (m['queries'] as num?)?.toInt() ?? 0,
    blocked: (m['blocked'] as num?)?.toInt() ?? 0,
    bypass: m['bypass'] as bool? ?? false,
  );

  final String app;
  final String label;
  final int queries;
  final int blocked;
  final bool bypass;

  bool get isPackage => app != 'unknown' && !app.startsWith('uid:');
}

class AppRules {
  const AppRules({required this.label, required this.allow, required this.block});

  final String label;
  final List<String> allow;
  final List<String> block;
}

class Rules {
  const Rules({this.allow = const [], this.block = const [], this.apps = const {}});

  factory Rules.fromMap(Map<Object?, Object?> m) {
    List<String> list(Object? v) => [for (final s in (v as List<Object?>? ?? const [])) s as String];
    final apps = <String, AppRules>{};
    for (final e in ((m['apps'] as Map<Object?, Object?>?) ?? const {}).entries) {
      final a = e.value as Map<Object?, Object?>;
      apps[e.key as String] = AppRules(
        label: a['label'] as String? ?? e.key as String,
        allow: list(a['allow']),
        block: list(a['block']),
      );
    }
    return Rules(allow: list(m['allow']), block: list(m['block']), apps: apps);
  }

  final List<String> allow;
  final List<String> block;
  final Map<String, AppRules> apps;
}

class InstalledApp {
  const InstalledApp({required this.app, required this.label, required this.system, required this.bypass});

  factory InstalledApp.fromMap(Map<Object?, Object?> m) => InstalledApp(
    app: m['app'] as String,
    label: m['label'] as String? ?? m['app'] as String,
    system: m['system'] as bool? ?? false,
    bypass: m['bypass'] as bool? ?? false,
  );

  final String app;
  final String label;
  final bool system;
  final bool bypass;
}

class UpdateResult {
  const UpdateResult({required this.domains, required this.failed});

  final int domains;
  final List<String> failed;
}

/// MethodChannel to MainActivity.kt.
class ShieldPlatform {
  const ShieldPlatform();

  static const _channel = MethodChannel('com.itsash.netshield/shield');

  Future<ShieldStatus> status() async =>
      ShieldStatus.fromMap(await _channel.invokeMapMethod<Object?, Object?>('status') ?? const {});

  /// Asks for the VPN permission when needed. False when the user said no.
  Future<bool> start() async => await _channel.invokeMethod<bool>('start') ?? false;

  Future<void> stop() => _channel.invokeMethod('stop');

  Future<void> setOption(String key, Object value) => _channel.invokeMethod('setOption', {'key': key, 'value': value});

  Future<List<ListInfo>> lists() async => [
    for (final m in await _channel.invokeListMethod<Map<Object?, Object?>>('lists') ?? const []) ListInfo.fromMap(m),
  ];

  Future<void> setListEnabled(String id, bool on) => _channel.invokeMethod('setListEnabled', {'id': id, 'on': on});

  /// Downloads (all when [force], else only missing or stale lists) and rebuilds.
  Future<UpdateResult> updateLists({bool force = false}) async {
    final m = await _channel.invokeMapMethod<Object?, Object?>('updateLists', {'force': force}) ?? const {};
    return UpdateResult(
      domains: (m['domains'] as num?)?.toInt() ?? 0,
      failed: [for (final s in (m['failed'] as List<Object?>? ?? const [])) s as String],
    );
  }

  /// Queries newer than [after], newest first.
  Future<List<LogEntry>> log({int after = 0, int limit = 500}) async => [
    for (final m in await _channel.invokeListMethod<Map<Object?, Object?>>('log', {'after': after, 'limit': limit}) ??
        const [])
      LogEntry.fromMap(m),
  ];

  Future<void> clearLog() => _channel.invokeMethod('clearLog');

  Future<List<AppStat>> appStats() async => [
    for (final m in await _channel.invokeListMethod<Map<Object?, Object?>>('appStats') ?? const []) AppStat.fromMap(m),
  ];

  Future<Rules> rules() async => Rules.fromMap(await _channel.invokeMapMethod<Object?, Object?>('rules') ?? const {});

  /// Saves a rule for everyone, or only for [app]. Returns the cleaned domain.
  /// Throws a [PlatformException] with a readable message for a bad domain.
  Future<String> addRule(String domain, {required bool allow, String? app}) async =>
      await _channel.invokeMethod<String>('addRule', {'domain': domain, 'allow': allow, 'app': app}) ?? domain;

  Future<void> removeRule(String domain, {required bool allow, String? app}) =>
      _channel.invokeMethod('removeRule', {'domain': domain, 'allow': allow, 'app': app});

  /// What NetShield would do with [domain]. Null when it is not a domain.
  Future<Verdict?> check(String domain, {String? app}) async {
    final v = await _channel.invokeMethod<int>('check', {'domain': domain, 'app': app}) ?? -1;
    return v < 0 ? null : Verdict.of(v);
  }

  Future<List<InstalledApp>> installedApps() async => [
    for (final m in await _channel.invokeListMethod<Map<Object?, Object?>>('installedApps') ?? const [])
      InstalledApp.fromMap(m),
  ];

  Future<void> setBypass(String app, bool on) => _channel.invokeMethod('setBypass', {'app': app, 'on': on});

  Future<Uint8List?> appIcon(String app) => _channel.invokeMethod<Uint8List>('appIcon', {'app': app});

  Future<void> openVpnSettings() => _channel.invokeMethod('openVpnSettings');

  Future<void> openNetworkSettings() => _channel.invokeMethod('openNetworkSettings');

  Future<void> requestNotifications() => _channel.invokeMethod('requestNotifications');
}
