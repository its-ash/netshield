import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';

/// Pick blocklists and update them. Changes apply after "Apply".
class ListsScreen extends StatefulWidget {
  const ListsScreen({super.key, required this.store});

  final ShieldStore store;

  @override
  State<ListsScreen> createState() => _ListsScreenState();
}

class _ListsScreenState extends State<ListsScreen> {
  List<ListInfo>? _lists;
  final Map<String, bool> _changed = {};

  ShieldStore get store => widget.store;

  @override
  void initState() {
    super.initState();
    store.watch();
    _load();
  }

  @override
  void dispose() {
    store.unwatch();
    super.dispose();
  }

  Future<void> _load() async {
    final l = await store.platform.lists();
    if (mounted) setState(() => _lists = l);
  }

  bool _on(ListInfo l) => _changed[l.id] ?? l.enabled;

  void _toggle(ListInfo l, bool on) {
    setState(() {
      if (on == l.enabled) {
        _changed.remove(l.id);
      } else {
        _changed[l.id] = on;
      }
    });
  }

  Future<void> _apply({bool force = false}) async {
    for (final e in _changed.entries) {
      await store.platform.setListEnabled(e.key, e.value);
    }
    try {
      final r = await store.updateLists(force: force);
      _changed.clear();
      await _load();
      if (!mounted) return;
      if (r.failed.isEmpty) {
        context.showToast('Blocking ${UiFormat.compact(r.domains)} domains.', status: UiStatus.success);
      } else {
        context.showToast(
          'Could not download ${r.failed.join(', ')}. The last copy is kept. Blocking ${UiFormat.compact(r.domains)} domains.',
          status: UiStatus.warning,
        );
      }
    } on PlatformException catch (e) {
      if (mounted) context.showToast(e.message ?? 'Update failed.', status: UiStatus.danger);
    }
  }

  @override
  Widget build(BuildContext context) {
    final lists = _lists;
    return UiScaffold(
      appBar: const UiAppBar(title: 'Blocklists'),
      scrollable: true,
      bottomBar: ListenableBuilder(
        listenable: store,
        builder: (context, _) => UiBottomBar(
          child: UiButton(
            _changed.isEmpty ? 'Update all lists now' : 'Apply changes',
            icon: _changed.isEmpty ? Icons.refresh_rounded : Icons.check_rounded,
            variant: _changed.isEmpty ? UiButtonVariant.outline : UiButtonVariant.primary,
            loading: store.busy,
            expand: true,
            onPressed: () => _apply(force: _changed.isEmpty),
          ),
        ),
      ),
      body: lists == null
          ? const UiSkeletonList(count: 6, avatar: false)
          : ListenableBuilder(
              listenable: store,
              builder: (context, _) {
                final s = store.status;
                final groups = <String, List<ListInfo>>{};
                for (final l in lists) {
                  groups.putIfAbsent(l.group, () => []).add(l);
                }
                final updated = s?.listsUpdatedAt;
                return UiColumn(
                  gap: UiSpace.lg,
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (store.busy && s?.updating != null)
                      UiProgressBar(null, label: s!.updating)
                    else
                      UiAlert(
                        s == null || !s.listsReady
                            ? 'Lists download the first time you turn NetShield on.'
                            : '${UiFormat.compact(s.domains)} domains blocked. '
                                  'Updated ${updated == null ? 'never' : UiFormat.relativeTime(updated)}; '
                                  'lists refresh by themselves every 3 days.',
                        status: UiStatus.info,
                      ),
                    for (final g in groups.entries)
                      UiListGroup(
                        header: g.key,
                        children: [
                          for (final l in g.value)
                            UiSwitchTile(
                              l.name,
                              subtitle: [
                                l.description,
                                if (l.count > 0) '${UiFormat.compact(l.count)} rules',
                                if (l.recommended) 'Recommended',
                              ].join(' · '),
                              value: _on(l),
                              onChanged: store.busy ? null : (v) => _toggle(l, v),
                            ),
                        ],
                      ),
                    Text(
                      'Lists by HaGeZi, OISD, AdGuard and StevenBlack, downloaded from their official sources. '
                      'More lists block more, but each extra list also costs memory and can break a site now and then. '
                      'Fix a broken site from the query log with "Allow".',
                      style: context.text.bodySmall,
                    ),
                  ],
                );
              },
            ),
    );
  }
}
