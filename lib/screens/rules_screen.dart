import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';
import '../widgets/app_icon.dart';
import 'apps_screen.dart';

/// Domains you always block or always allow, plus the apps with their own rules.
class RulesScreen extends StatefulWidget {
  const RulesScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<RulesScreen> createState() => _RulesScreenState();
}

class _RulesScreenState extends State<RulesScreen> {
  Rules? _rules;

  ShieldPlatform get platform => widget.store.platform;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final r = await platform.rules();
    if (mounted) setState(() => _rules = r);
  }

  Future<void> _add(bool allow) async {
    final d = await UiDialog.prompt(
      context,
      title: allow ? 'Always allow' : 'Always block',
      message: 'The domain and all its subdomains, in every app.',
      label: 'Domain',
      hint: allow ? 'shop.example.com' : 'ads.example.com',
      confirmLabel: allow ? 'Allow' : 'Block',
      keyboardType: TextInputType.url,
    );
    if (d == null || d.trim().isEmpty || !mounted) return;
    try {
      await platform.addRule(d, allow: allow);
      await _load();
    } on PlatformException catch (e) {
      if (mounted) context.showToast(e.message ?? 'Not a domain.', status: UiStatus.danger);
    }
  }

  Future<void> _remove(String d, bool allow) async {
    await platform.removeRule(d, allow: allow);
    await _load();
  }

  Widget _group(String header, String footer, List<String> domains, bool allow) {
    return UiListGroup(
      header: header,
      footer: footer,
      children: [
        for (final d in domains)
          UiListTile(
            d,
            icon: allow ? Icons.check_rounded : Icons.block_rounded,
            iconStatus: allow ? UiStatus.success : UiStatus.danger,
            dense: true,
            trailing: UiIconButton(Icons.close_rounded, tooltip: 'Remove', size: UiSize.sm, onPressed: () => _remove(d, allow)),
          ),
        UiListTile(
          allow ? 'Allow a domain' : 'Block a domain',
          icon: Icons.add_rounded,
          iconStatus: UiStatus.neutral,
          onTap: () => _add(allow),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final r = _rules;
    return UiScaffold(
      appBar: const UiAppBar(title: 'My rules'),
      scrollable: true,
      onRefresh: _load,
      body: r == null
          ? const UiSkeletonList(count: 4, avatar: false)
          : UiColumn(
              gap: UiSpace.lg,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _group(
                  'Always block',
                  'Blocked even when no list has them.',
                  r.block,
                  false,
                ),
                _group(
                  'Always allow',
                  'Never blocked, even when a list has them. Use this to fix a site or app that breaks.',
                  r.allow,
                  true,
                ),
                if (r.apps.isNotEmpty)
                  UiListGroup(
                    header: 'Apps with their own rules',
                    footer: 'An app rule wins over the rules above.',
                    children: [
                      for (final e in r.apps.entries)
                        UiListTile(
                          e.value.label,
                          subtitle: '${e.value.block.length} blocked · ${e.value.allow.length} allowed',
                          leading: AppIcon(e.key),
                          chevron: true,
                          onTap: () async {
                            await Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) => AppDetailScreen(store: widget.store, app: e.key, label: e.value.label),
                              ),
                            );
                            await _load();
                          },
                        ),
                    ],
                  ),
              ],
            ),
    );
  }
}
