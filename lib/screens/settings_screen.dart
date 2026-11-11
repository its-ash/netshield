import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';
import 'bypass_screen.dart';
import 'lists_screen.dart';
import 'rules_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
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

  Future<void> _set(String key, Object value) async {
    await store.platform.setOption(key, value);
    await store.refresh();
  }

  Future<void> _alwaysOn() async {
    final go = await UiDialog.confirm(
      context,
      title: 'Always-on VPN',
      message:
          'Android can keep NetShield on all the time and start it after a reboot. In VPN settings, tap the gear '
          'next to NetShield and turn on "Always-on VPN". Leave "Block connections without VPN" off, or apps '
          'you set to skip NetShield lose internet.',
      confirmLabel: 'Open VPN settings',
    );
    if (go) await store.platform.openVpnSettings();
  }

  Future<void> _check() async {
    final d = await UiDialog.prompt(
      context,
      title: 'Check a domain',
      message: 'See what NetShield does with a domain, without opening it.',
      label: 'Domain',
      hint: 'ads.example.com',
      confirmLabel: 'Check',
      keyboardType: TextInputType.url,
    );
    if (d == null || d.trim().isEmpty || !mounted) return;
    final v = await store.platform.check(d);
    if (!mounted) return;
    if (v == null) {
      context.showToast('That is not a domain.', status: UiStatus.danger);
      return;
    }
    await UiDialog.alert(
      context,
      title: v.blocked ? 'Blocked' : 'Allowed',
      message: '${d.trim()}: ${v.label}.'
          '${v == Verdict.allowed ? ' A hidden tracker behind it (CNAME) would still be caught when it is opened.' : ''}',
      status: v.blocked ? UiStatus.danger : UiStatus.success,
    );
  }

  String _privateDns(ShieldStatus s) => switch (s.privateDnsMode) {
    'hostname' => 'On: ${s.privateDnsHost ?? 'custom'}',
    'opportunistic' => 'Automatic',
    'off' => 'Off',
    _ => 'Unknown',
  };

  @override
  Widget build(BuildContext context) {
    return UiScaffold(
      appBar: const UiAppBar(title: 'Settings'),
      scrollable: true,
      body: ListenableBuilder(
        listenable: store,
        builder: (context, _) {
          final s = store.status;
          if (s == null) return const Center(child: UiSpinner());
          return UiColumn(
            gap: UiSpace.lg,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              UiListGroup(
                header: 'DNS server',
                footer: 'Requests that are not blocked go here, encrypted (DNS over HTTPS), so your network '
                    'cannot read or change them.',
                children: [
                  for (final u in Upstream.values)
                    UiRadioTile<Upstream>(
                      u.label,
                      subtitle: u.description,
                      value: u,
                      groupValue: s.upstream,
                      onChanged: (v) => _set('upstream', v.key),
                    ),
                ],
              ),
              UiListGroup(
                header: 'Bypass protection',
                footer: 'Some apps and browsers use their own DNS server to get around blockers. NetShield '
                    'catches DNS sent to Google, Cloudflare, Quad9, AdGuard and other public servers, and stops '
                    'their encrypted DNS so the app falls back to NetShield.',
                children: [
                  UiSwitchTile(
                    "Catch apps' own DNS",
                    icon: Icons.policy_rounded,
                    value: s.interceptDns,
                    onChanged: (v) => _set('interceptDns', v),
                  ),
                  UiListTile(
                    'Private DNS',
                    subtitle: s.privateDnsBypass
                        ? 'Skips NetShield. Set it to Off or Automatic.'
                        : 'Must be Off or Automatic for NetShield to work.',
                    icon: Icons.lock_outline_rounded,
                    iconStatus: s.privateDnsBypass ? UiStatus.warning : UiStatus.accent,
                    value: _privateDns(s),
                    chevron: true,
                    onTap: store.platform.openNetworkSettings,
                  ),
                ],
              ),
              UiListGroup(
                header: 'Apps and startup',
                children: [
                  UiListTile(
                    'Apps that skip NetShield',
                    subtitle: 'For apps that break while NetShield is on',
                    icon: Icons.alt_route_rounded,
                    chevron: true,
                    onTap: () => _open(BypassScreen(store: store)),
                  ),
                  UiListTile(
                    'Always-on VPN',
                    subtitle: 'Keep NetShield on, even after a reboot',
                    icon: Icons.vpn_lock_rounded,
                    chevron: true,
                    onTap: _alwaysOn,
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
                    icon: Icons.rule_rounded,
                    chevron: true,
                    onTap: () => _open(RulesScreen(store: store)),
                  ),
                  UiListTile(
                    'Check a domain',
                    icon: Icons.travel_explore_rounded,
                    chevron: true,
                    onTap: _check,
                  ),
                ],
              ),
              const UiAppearanceSection(),
              const UiUpdateSection(storeId: 'netshield'),
              const UiDeveloperSection(),
            ],
          );
        },
      ),
    );
  }
}
