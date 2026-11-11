import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';
import '../widgets/app_icon.dart';

/// Pick apps that go around NetShield completely.
class BypassScreen extends StatefulWidget {
  const BypassScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<BypassScreen> createState() => _BypassScreenState();
}

class _BypassScreenState extends State<BypassScreen> {
  List<InstalledApp>? _apps;
  final Map<String, bool> _bypass = {};
  String _query = '';
  bool _system = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final apps = await widget.store.platform.installedApps();
    if (!mounted) return;
    setState(() {
      _apps = apps;
      for (final a in apps) {
        _bypass[a.app] = a.bypass;
      }
    });
  }

  Future<void> _set(InstalledApp a, bool on) async {
    setState(() => _bypass[a.app] = on);
    await widget.store.platform.setBypass(a.app, on);
  }

  @override
  Widget build(BuildContext context) {
    final apps = _apps;
    final shown = apps
        ?.where((a) => _system || !a.system || (_bypass[a.app] ?? false))
        .where((a) => _query.isEmpty || a.label.toLowerCase().contains(_query) || a.app.contains(_query))
        .toList();
    shown?.sort((x, y) {
      final bx = (_bypass[x.app] ?? false) ? 0 : 1;
      final by = (_bypass[y.app] ?? false) ? 0 : 1;
      return bx != by ? bx - by : x.label.toLowerCase().compareTo(y.label.toLowerCase());
    });
    return UiScaffold(
      appBar: const UiAppBar(title: 'Apps that skip NetShield'),
      scrollable: true,
      body: UiColumn(
        gap: UiSpace.lg,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const UiAlert(
            'These apps use the internet directly: nothing they load is filtered. Use it only for apps that break, '
            'for example a banking app that refuses to work behind a VPN.',
            status: UiStatus.info,
          ),
          UiSearchField(hint: 'Search apps', onChanged: (v) => setState(() => _query = v.trim().toLowerCase())),
          UiSwitch(_system, label: 'Show system apps', onChanged: (v) => setState(() => _system = v)),
          if (shown == null)
            const UiSkeletonList(count: 8)
          else if (shown.isEmpty)
            const UiEmptyState(title: 'No apps found', icon: Icons.search_off_rounded, compact: true)
          else
            UiListGroup(
              children: [
                for (final a in shown)
                  UiListTile(
                    a.label,
                    subtitle: a.app,
                    leading: AppIcon(a.app),
                    trailing: UiSwitch(_bypass[a.app] ?? false, onChanged: (v) => _set(a, v)),
                    onTap: () => _set(a, !(_bypass[a.app] ?? false)),
                  ),
              ],
            ),
        ],
      ),
    );
  }
}
