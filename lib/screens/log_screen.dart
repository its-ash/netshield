import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import '../shield/shield_store.dart';
import '../widgets/log_tile.dart';

enum _Filter { all, blocked, allowed }

/// Every request NetShield answered while the app was open, newest first.
/// With [app] it shows only that app's requests.
class LogScreen extends StatefulWidget {
  const LogScreen({super.key, required this.store, this.app, this.appLabel, this.blockedOnly = false});

  final ShieldStore store;
  final String? app;
  final String? appLabel;
  final bool blockedOnly;

  @override
  State<LogScreen> createState() => _LogScreenState();
}

class _LogScreenState extends State<LogScreen> {
  late _Filter _filter = widget.blockedOnly ? _Filter.blocked : _Filter.all;
  String _query = '';

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

  bool _keep(LogEntry e) {
    if (widget.app != null && e.app != widget.app) return false;
    if (_filter == _Filter.blocked && !e.verdict.blocked) return false;
    if (_filter == _Filter.allowed && e.verdict.blocked) return false;
    if (_query.isNotEmpty && !e.domain.contains(_query) && !e.label.toLowerCase().contains(_query)) return false;
    return true;
  }

  Future<void> _clear() async {
    final ok = await UiDialog.confirm(
      context,
      title: 'Clear the log?',
      message: 'Removes the request history and the per-app counts. Today\'s totals stay.',
      confirmLabel: 'Clear',
      destructive: true,
    );
    if (ok) await store.clearLog();
  }

  @override
  Widget build(BuildContext context) {
    return UiScaffold(
      appBar: UiAppBar(
        title: widget.appLabel ?? 'Query log',
        subtitle: widget.app != null ? 'Requests from this app' : null,
        actions: [
          if (widget.app == null)
            UiIconButton(Icons.delete_sweep_rounded, tooltip: 'Clear the log', onPressed: _clear),
        ],
      ),
      padding: EdgeInsets.zero,
      body: ListenableBuilder(
        listenable: store,
        builder: (context, _) {
          final items = store.log.where(_keep).toList();
          final running = store.status?.running ?? false;
          final side = UiContent.pagePadding(context);
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Padding(
                padding: EdgeInsets.fromLTRB(side, UiSpace.lg, side, UiSpace.sm),
                child: UiSearchField(
                  hint: 'Search domains or apps',
                  onChanged: (v) => setState(() => _query = v.trim().toLowerCase()),
                ),
              ),
              Padding(
                padding: EdgeInsets.symmetric(horizontal: side, vertical: UiSpace.xs),
                child: UiChoiceChips<_Filter>(
                  options: const [
                    UiChoice(_Filter.all, 'All'),
                    UiChoice(_Filter.blocked, 'Blocked', icon: Icons.block_rounded),
                    UiChoice(_Filter.allowed, 'Allowed', icon: Icons.check_rounded),
                  ],
                  value: _filter,
                  size: UiSize.sm,
                  onChanged: (v) => setState(() => _filter = v),
                ),
              ),
              Expanded(
                child: items.isEmpty
                    ? UiEmptyState(
                        title: store.log.isEmpty ? 'No requests yet' : 'Nothing matches',
                        message: store.log.isEmpty
                            ? (running
                                  ? 'Open an app or a website and its requests show up here.'
                                  : 'Turn NetShield on to see requests.')
                            : 'Try another search or filter.',
                        icon: Icons.receipt_long_rounded,
                      )
                    : ListView.builder(
                        padding: EdgeInsets.fromLTRB(side, UiSpace.sm, side, UiSpace.xl),
                        itemCount: items.length,
                        itemBuilder: (context, i) => LogTile(items[i], showApp: widget.app == null),
                      ),
              ),
            ],
          );
        },
      ),
    );
  }
}
