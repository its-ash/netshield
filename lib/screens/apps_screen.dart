import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';
import '../widgets/app_icon.dart';
import '../widgets/log_tile.dart';
import 'log_screen.dart';

/// Requests and blocks per app since NetShield started.
class AppsScreen extends StatefulWidget {
  const AppsScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<AppsScreen> createState() => _AppsScreenState();
}

class _AppsScreenState extends State<AppsScreen> {
  List<AppStat>? _apps;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _load();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final a = await widget.store.platform.appStats();
      a.sort((x, y) => y.queries.compareTo(x.queries));
      if (mounted) setState(() => _apps = a);
    } on PlatformException {
      // Keep the last list.
    }
  }

  @override
  Widget build(BuildContext context) {
    final apps = _apps;
    final perApp = widget.store.status?.perApp ?? true;
    return UiScaffold(
      appBar: const UiAppBar(title: 'Apps'),
      scrollable: true,
      onRefresh: _load,
      body: apps == null
          ? const UiSkeletonList(count: 6)
          : UiColumn(
              gap: UiSpace.lg,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (!perApp)
                  const UiAlert(
                    'Android 9 and older cannot tell which app made a request, so all requests are counted together.',
                    status: UiStatus.info,
                  ),
                if (apps.any((a) => a.app == 'uid:1051'))
                  const UiAlert(
                    'Some requests came through Android\'s own DNS resolver, which hides the app behind it. '
                    'They are listed as "Android DNS resolver".',
                    status: UiStatus.info,
                  ),
                if (apps.isEmpty)
                  const UiEmptyState(
                    title: 'No requests yet',
                    message: 'Use your phone for a moment with NetShield on, then come back.',
                    icon: Icons.apps_rounded,
                  )
                else
                  UiListGroup(
                    footer: 'Counts start when NetShield starts. Tap an app to see its requests and set rules for it.',
                    children: [
                      for (final a in apps)
                        UiListTile(
                          a.label,
                          subtitle:
                              '${UiFormat.compact(a.queries)} requests · ${UiFormat.compact(a.blocked)} blocked'
                              '${a.bypass ? ' · skips NetShield' : ''}',
                          leading: AppIcon(a.app),
                          trailing: UiStatusPill(
                            '${a.queries == 0 ? 0 : (a.blocked * 100 / a.queries).round()}%',
                            status: a.blocked == 0 ? UiStatus.neutral : UiStatus.danger,
                          ),
                          chevron: true,
                          onTap: () => Navigator.of(context).push(
                            MaterialPageRoute<void>(
                              builder: (_) => a.isPackage
                                  ? AppDetailScreen(store: widget.store, app: a.app, label: a.label)
                                  : LogScreen(store: widget.store, app: a.app, appLabel: a.label),
                            ),
                          ),
                        ),
                    ],
                  ),
              ],
            ),
    );
  }
}

/// One app: skip NetShield for it, its own rules, and the domains it asks for most.
class AppDetailScreen extends StatefulWidget {
  const AppDetailScreen({super.key, required this.store, required this.app, required this.label});

  final ShieldStore store;
  final String app;
  final String label;

  @override
  State<AppDetailScreen> createState() => _AppDetailScreenState();
}

class _AppDetailScreenState extends State<AppDetailScreen> {
  AppRules _rules = const AppRules(label: '', allow: [], block: []);
  bool? _bypass;

  ShieldPlatform get platform => widget.store.platform;

  @override
  void initState() {
    super.initState();
    widget.store.watch();
    _load();
  }

  @override
  void dispose() {
    widget.store.unwatch();
    super.dispose();
  }

  Future<void> _load() async {
    final r = await platform.rules();
    if (!mounted) return;
    setState(() => _rules = r.apps[widget.app] ?? const AppRules(label: '', allow: [], block: []));
    if (_bypass == null) {
      // Read once; after that the switch keeps its own state.
      var b = (await platform.appStats()).where((s) => s.app == widget.app).firstOrNull?.bypass;
      b ??= (await platform.installedApps()).where((a) => a.app == widget.app).firstOrNull?.bypass;
      if (mounted) setState(() => _bypass = b ?? false);
    }
  }

  Future<void> _setBypass(bool on) async {
    setState(() => _bypass = on);
    await platform.setBypass(widget.app, on);
    if (mounted) {
      context.showToast(on ? '${widget.label} now skips NetShield.' : '${widget.label} is filtered again.');
    }
  }

  Future<void> _addRule(bool allow) async {
    final d = await UiDialog.prompt(
      context,
      title: allow ? 'Allow a domain in ${widget.label}' : 'Block a domain in ${widget.label}',
      label: 'Domain',
      hint: 'ads.example.com',
      confirmLabel: allow ? 'Allow' : 'Block',
      keyboardType: TextInputType.url,
    );
    if (d == null || d.trim().isEmpty || !mounted) return;
    try {
      await platform.addRule(d, allow: allow, app: widget.app);
      await _load();
    } on PlatformException catch (e) {
      if (mounted) context.showToast(e.message ?? 'Not a domain.', status: UiStatus.danger);
    }
  }

  Future<void> _remove(String domain, bool allow) async {
    await platform.removeRule(domain, allow: allow, app: widget.app);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    return UiScaffold(
      appBar: UiAppBar(title: widget.label, subtitle: widget.app),
      scrollable: true,
      body: ListenableBuilder(
        listenable: widget.store,
        builder: (context, _) {
          final mine = widget.store.log.where((e) => e.app == widget.app).toList();
          final blocked = mine.where((e) => e.verdict.blocked).length;
          final counts = <String, int>{};
          for (final e in mine) {
            counts[e.domain] = (counts[e.domain] ?? 0) + 1;
          }
          final top = counts.entries.toList()..sort((a, b) => b.value.compareTo(a.value));
          final lastVerdict = {for (final e in mine.reversed) e.domain: e};
          return UiColumn(
            gap: UiSpace.lg,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              UiRow(
                gap: UiSpace.lg,
                children: [
                  AppIcon(widget.app, size: 56),
                  Expanded(
                    child: Text(
                      '${mine.length} requests while the app was open, $blocked blocked.',
                      style: context.text.bodyMedium,
                    ),
                  ),
                ],
              ),
              UiListGroup(
                footer: 'Use this when the app breaks with NetShield on. Its requests are not filtered at all.',
                children: [
                  UiSwitchTile(
                    'Skip NetShield for this app',
                    icon: Icons.alt_route_rounded,
                    value: _bypass ?? false,
                    onChanged: _bypass == null ? null : _setBypass,
                  ),
                ],
              ),
              _RuleGroup(
                header: 'Blocked only in this app',
                domains: _rules.block,
                allow: false,
                onAdd: () => _addRule(false),
                onRemove: (d) => _remove(d, false),
              ),
              _RuleGroup(
                header: 'Allowed only in this app',
                domains: _rules.allow,
                allow: true,
                onAdd: () => _addRule(true),
                onRemove: (d) => _remove(d, true),
              ),
              if (top.isNotEmpty)
                UiSection(
                  title: 'Most requested',
                  actionLabel: 'All requests',
                  onAction: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(
                      builder: (_) => LogScreen(store: widget.store, app: widget.app, appLabel: widget.label),
                    ),
                  ),
                  child: UiListGroup(
                    children: [
                      for (final t in top.take(15))
                        UiListTile(
                          t.key,
                          subtitle: '${t.value}× · ${lastVerdict[t.key]!.verdict.label}',
                          icon: lastVerdict[t.key]!.verdict.blocked ? Icons.block_rounded : Icons.check_rounded,
                          iconStatus: lastVerdict[t.key]!.verdict.blocked ? UiStatus.danger : UiStatus.success,
                          dense: true,
                          onTap: () async {
                            if (await showRuleActions(
                              context,
                              domain: t.key,
                              app: widget.app,
                              appLabel: widget.label,
                              entry: lastVerdict[t.key],
                            )) {
                              await _load();
                            }
                          },
                        ),
                    ],
                  ),
                ),
            ],
          );
        },
      ),
    );
  }
}

class _RuleGroup extends StatelessWidget {
  const _RuleGroup({
    required this.header,
    required this.domains,
    required this.allow,
    required this.onAdd,
    required this.onRemove,
  });

  final String header;
  final List<String> domains;
  final bool allow;
  final VoidCallback onAdd;
  final ValueChanged<String> onRemove;

  @override
  Widget build(BuildContext context) {
    return UiListGroup(
      header: header,
      children: [
        for (final d in domains)
          UiListTile(
            d,
            icon: allow ? Icons.check_rounded : Icons.block_rounded,
            iconStatus: allow ? UiStatus.success : UiStatus.danger,
            dense: true,
            trailing: UiIconButton(Icons.close_rounded, tooltip: 'Remove', size: UiSize.sm, onPressed: () => onRemove(d)),
          ),
        UiListTile(
          allow ? 'Allow a domain' : 'Block a domain',
          icon: Icons.add_rounded,
          iconStatus: UiStatus.neutral,
          onTap: onAdd,
        ),
      ],
    );
  }
}
