import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:theme/theme.dart';

import '../shield/shield_platform.dart';
import 'app_icon.dart';

String clock(DateTime t) =>
    '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

/// One request in the log: domain, app, time and whether it was blocked.
class LogTile extends StatelessWidget {
  const LogTile(this.entry, {super.key, this.showApp = true, this.onChanged});

  final LogEntry entry;
  final bool showApp;

  /// Called after the user added a rule from the action sheet.
  final VoidCallback? onChanged;

  @override
  Widget build(BuildContext context) {
    final e = entry;
    final v = e.verdict;
    return UiListTile(
      e.domain,
      subtitle: [if (showApp) e.label, clock(e.time), if (v != Verdict.allowed) v.label].join(' · '),
      leading: showApp ? AppIcon(e.app) : null,
      icon: showApp ? null : (v.blocked ? Icons.block_rounded : Icons.check_rounded),
      iconStatus: v.blocked ? UiStatus.danger : UiStatus.success,
      trailing: UiStatusPill(
        v.blocked ? 'Blocked' : (v == Verdict.error ? 'Failed' : 'Allowed'),
        status: v.blocked ? UiStatus.danger : (v == Verdict.error ? UiStatus.warning : UiStatus.success),
      ),
      dense: true,
      onTap: () async {
        if (await showRuleActions(context, domain: e.domain, app: e.isPackage ? e.app : null, appLabel: e.label, entry: e)) {
          onChanged?.call();
        }
      },
    );
  }
}

/// Block or allow [domain] everywhere or only for [app]. True when a rule was saved.
Future<bool> showRuleActions(
  BuildContext context, {
  required String domain,
  String? app,
  String? appLabel,
  LogEntry? entry,
  ShieldPlatform platform = const ShieldPlatform(),
}) async {
  final details = entry == null
      ? null
      : [
          entry.verdict.label,
          '${entry.typeName} request',
          if (entry.detail != null)
            entry.verdict == Verdict.blockedCname ? 'hides ${entry.detail}' : 'answer ${entry.detail}',
          '${entry.ms} ms',
        ].join(' · ');
  final action = await UiActionSheet.show<String>(
    context,
    title: domain,
    message: details,
    actions: [
      const UiSheetAction('Block everywhere', value: 'block', icon: Icons.block_rounded, destructive: true),
      const UiSheetAction('Allow everywhere', value: 'allow', icon: Icons.check_circle_outline_rounded),
      if (app != null) ...[
        UiSheetAction('Block only in ${appLabel ?? app}', value: 'block-app', icon: Icons.phonelink_lock_rounded),
        UiSheetAction('Allow only in ${appLabel ?? app}', value: 'allow-app', icon: Icons.phonelink_rounded),
      ],
      const UiSheetAction('Copy domain', value: 'copy', icon: Icons.copy_rounded),
    ],
  );
  if (action == null || !context.mounted) return false;
  if (action == 'copy') {
    await Clipboard.setData(ClipboardData(text: domain));
    if (context.mounted) context.showToast('Copied $domain');
    return false;
  }
  final allow = action.startsWith('allow');
  final forApp = action.endsWith('-app') ? app : null;
  try {
    final d = await platform.addRule(domain, allow: allow, app: forApp);
    if (context.mounted) {
      final where = forApp == null ? 'everywhere' : 'in ${appLabel ?? app}';
      context.showToast(
        '${allow ? 'Allowed' : 'Blocked'} $d $where. Apps may keep a cached answer for a minute.',
        status: UiStatus.success,
      );
    }
    return true;
  } on PlatformException catch (e) {
    if (context.mounted) context.showToast(e.message ?? 'Could not save the rule.', status: UiStatus.danger);
    return false;
  }
}
