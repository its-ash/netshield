import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import '../shield/shield_store.dart';
import '../widgets/log_tile.dart';
import 'apps_screen.dart';
import 'lists_screen.dart';
import 'log_screen.dart';
import 'rules_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  ShieldStore get store => widget.store;

  @override
  void initState() {
    super.initState();
    store.watch();
  }

  @override
  void dispose() {
    store.unwatch();
    super.dispose();
  }

  void _open(Widget screen) => Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => screen));

  Future<void> _toggle() async {
    final s = store.status;
    if (s?.running == true) {
      final ok = await UiDialog.confirm(
        context,
        title: 'Turn off NetShield?',
        message: 'Ads and trackers will load again in every app until you turn it back on.',
        confirmLabel: 'Turn off',
        destructive: true,
      );
      if (ok) await store.turnOff();
      return;
    }
    final err = await store.turnOn();
    if (!mounted) return;
    if (err != null) {
      context.showToast(err, status: UiStatus.danger);
    } else if (store.status?.notifications == false) {
      await store.platform.requestNotifications();
    }
  }

  @override
  Widget build(BuildContext context) {
    return UiScaffold(
      appBar: UiAppBar(
        title: 'NetShield',
        actions: [
          UiIconButton(
            Icons.settings_rounded,
            tooltip: 'Settings',
            onPressed: () => _open(SettingsScreen(store: store)),
          ),
        ],
      ),
      scrollable: true,
      onRefresh: store.refresh,
      body: ListenableBuilder(
        listenable: store,
        builder: (context, _) {
          final s = store.status;
          if (s == null) return const Padding(padding: EdgeInsets.all(UiSpace.xxl), child: Center(child: UiSpinner()));
          final recentBlocked = store.log.where((e) => e.verdict.blocked).take(5).toList();
          return UiColumn(
            gap: UiSpace.lg,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _StatusCard(store: store, onToggle: _toggle),
              if (s.error != null && !s.running && !store.busy)
                UiAlert(s.error!, title: 'NetShield is off', status: UiStatus.danger),
              if (s.privateDnsBypass)
                UiAlert(
                  'Android sends DNS straight to ${s.privateDnsHost ?? 'your Private DNS provider'}, so NetShield '
                  'cannot filter anything. Set Private DNS to Off or Automatic.',
                  title: 'Private DNS skips NetShield',
                  status: UiStatus.warning,
                  action: UiButton(
                    'Open network settings',
                    variant: UiButtonVariant.soft,
                    size: UiSize.sm,
                    onPressed: store.platform.openNetworkSettings,
                  ),
                ),
              UiResponsiveGrid(
                minItemWidth: 140,
                equalHeight: true,
                children: [
                  UiStatCard(
                    label: 'Requests today',
                    value: UiFormat.compact(s.today),
                    icon: Icons.dns_rounded,
                  ),
                  UiStatCard(
                    label: 'Blocked today',
                    value: UiFormat.compact(s.todayBlocked),
                    icon: Icons.block_rounded,
                    iconStatus: UiStatus.danger,
                    footer: Text(
                      '${(s.blockedShare * 100).toStringAsFixed(1)}% of requests',
                      style: context.text.bodySmall,
                    ),
                  ),
                ],
              ),
              UiListGroup(
                header: 'Activity',
                children: [
                  UiListTile(
                    'Query log',
                    subtitle: 'Every request, with the app that made it',
                    icon: Icons.receipt_long_rounded,
                    chevron: true,
                    onTap: () => _open(LogScreen(store: store)),
                  ),
                  UiListTile(
                    'Apps',
                    subtitle: s.perApp ? 'Requests and blocks per app' : 'Needs Android 10 or newer',
                    icon: Icons.apps_rounded,
                    chevron: true,
                    onTap: () => _open(AppsScreen(store: store)),
                  ),
                ],
              ),
              UiListGroup(
                header: 'Filtering',
                children: [
                  UiListTile(
                    'Blocklists',
                    subtitle: s.listsReady ? '${UiFormat.compact(s.domains)} domains' : 'Not downloaded yet',
                    icon: Icons.shield_rounded,
                    chevron: true,
                    onTap: () => _open(ListsScreen(store: store)),
                  ),
                  UiListTile(
                    'My rules',
                    subtitle: 'Domains you always block or allow',
                    icon: Icons.rule_rounded,
                    chevron: true,
                    onTap: () => _open(RulesScreen(store: store)),
                  ),
                ],
              ),
              if (recentBlocked.isNotEmpty)
                UiSection(
                  title: 'Just blocked',
                  actionLabel: 'See all',
                  onAction: () => _open(LogScreen(store: store, blockedOnly: true)),
                  child: UiListGroup(children: [for (final e in recentBlocked) LogTile(e)]),
                ),
            ],
          );
        },
      ),
    );
  }
}

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.store, required this.onToggle});

  final ShieldStore store;
  final VoidCallback onToggle;

  @override
  Widget build(BuildContext context) {
    final s = store.status!;
    final on = s.running;
    final updating = s.updating;
    final String detail;
    if (store.busy && updating != null) {
      detail = updating;
    } else if (on) {
      detail = 'Ads, trackers and malware are blocked in every app and browser.';
    } else {
      detail = s.listsReady
          ? 'Turn on to block ads in every app and browser.'
          : 'Turn on to download the blocklists and start blocking.';
    }
    return UiSurface(
      tone: on ? UiStatus.success : null,
      padding: const EdgeInsets.all(UiSpace.xl),
      child: UiColumn(
        gap: UiSpace.lg,
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          UiIconBox(
            on ? Icons.verified_user_rounded : Icons.shield_outlined,
            status: on ? UiStatus.success : UiStatus.neutral,
            size: 72,
            solid: on,
          ),
          UiColumn(
            gap: UiSpace.xs,
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Text(on ? 'Protected' : 'Not protected', style: context.text.headlineSmall),
              Text(detail, style: context.text.bodyMedium?.copyWith(color: context.colors.textMuted), textAlign: TextAlign.center),
            ],
          ),
          if (store.busy && updating != null) const UiProgressBar(null),
          UiButton(
            on ? 'Turn off' : 'Turn on',
            icon: on ? Icons.power_settings_new_rounded : Icons.shield_rounded,
            variant: on ? UiButtonVariant.outline : UiButtonVariant.primary,
            size: UiSize.lg,
            expand: true,
            loading: store.busy,
            onPressed: onToggle,
          ),
        ],
      ),
    );
  }
}
