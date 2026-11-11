import 'package:flutter_test/flutter_test.dart';
import 'package:netshield/shield/shield_platform.dart';

void main() {
  test('verdict numbers match Filter.kt', () {
    expect(Verdict.of(0), Verdict.allowed);
    expect(Verdict.of(1), Verdict.blockedList);
    expect(Verdict.of(4), Verdict.blockedCname);
    expect(Verdict.of(5), Verdict.blockedUpstream);
    expect(Verdict.of(6), Verdict.allowedRule);
    expect(Verdict.of(7), Verdict.error);
    expect(Verdict.of(99), Verdict.allowed);
    expect([for (final v in Verdict.values) if (v.blocked) v.index], [1, 2, 3, 4, 5]);
  });

  test('status parses with safe defaults', () {
    final s = ShieldStatus.fromMap(const {});
    expect(s.running, isFalse);
    expect(s.upstream, Upstream.adguard);
    expect(s.interceptDns, isTrue);
    expect(s.listsUpdatedAt, isNull);
    expect(s.blockedShare, 0);

    final t = ShieldStatus.fromMap(const {
      'running': true,
      'upstream': 'quad9',
      'privateDnsMode': 'hostname',
      'privateDnsHost': 'dns.example',
      'today': 200,
      'todayBlocked': 50,
      'listsUpdatedAt': 1700000000000,
    });
    expect(t.running, isTrue);
    expect(t.upstream, Upstream.quad9);
    expect(t.privateDnsBypass, isTrue);
    expect(t.blockedShare, 0.25);
    expect(t.listsUpdatedAt, isNotNull);
  });

  test('log entry knows real apps from system processes', () {
    LogEntry entry(String app, int type) => LogEntry.fromMap({
      'id': 1,
      'time': 0,
      'domain': 'ads.example.com',
      'type': type,
      'app': app,
      'label': 'X',
      'verdict': 1,
      'ms': 3,
    });
    expect(entry('com.game', 1).isPackage, isTrue);
    expect(entry('uid:1000', 28).isPackage, isFalse);
    expect(entry('unknown', 65).isPackage, isFalse);
    expect(entry('com.game', 1).typeName, 'A');
    expect(entry('com.game', 28).typeName, 'AAAA');
    expect(entry('com.game', 65).typeName, 'HTTPS');
    expect(entry('com.game', 1).verdict.blocked, isTrue);
  });

  test('rules parse app sections', () {
    final r = Rules.fromMap(const {
      'allow': ['ok.com'],
      'block': ['ads.com', 'track.com'],
      'apps': {
        'com.bank': {'label': 'Bank', 'allow': ['cdn.bank.com'], 'block': []},
      },
    });
    expect(r.allow, ['ok.com']);
    expect(r.block, hasLength(2));
    expect(r.apps['com.bank']!.label, 'Bank');
    expect(r.apps['com.bank']!.allow, ['cdn.bank.com']);
    expect(Rules.fromMap(const {}).apps, isEmpty);
  });

  test('upstream keys round trip', () {
    for (final u in Upstream.values) {
      expect(Upstream.of(u.key), u);
    }
    expect(Upstream.of('nope'), Upstream.adguard);
  });
}
