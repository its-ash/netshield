# NetShield (package: netshield / com.itsash.netshield)

Whole-phone ad, tracker and malware blocker. A Kotlin `VpnService` runs a
DNS-only tunnel: only DNS goes through it, every query is checked against the
user's rules and the compiled blocklists, blocked names get 0.0.0.0 / :: and the
rest goes to a DNS-over-HTTPS upstream. Flutter is only the UI.

## How the tunnel works (`ShieldVpnService.kt`)

- Interface 10.111.222.1/32 + fd00:6e73::1/128; DNS servers 10.111.222.2 and
  fd00:6e73::2, routed into the tunnel as /32 and /128. Nothing else is routed, so
  normal traffic never touches NetShield.
- "Catch apps' own DNS" (`interceptDns`, default on) also routes `HARDCODED_V4/V6`
  (public resolvers) into the tunnel: their UDP 53 is filtered like normal DNS,
  TCP to them (DoH, DoT, DNS over TCP) gets a TCP reset (`Packets.tcpReset`) so apps
  fall back to plain DNS, other UDP (QUIC/DoQ) is dropped.
- NetShield excludes itself (`addDisallowedApplication(packageName)`), so its DoH
  upstream and list downloads use the real network and never loop. Bypass apps are
  excluded the same way; changing them or `interceptDns` restarts the tunnel.
- Non-blocking tun fd + `Os.poll` with a wake pipe: `closeTun()` always ends the
  reader thread (a blocking read on a closed tun fd can hang).
- Per query (pool of 8): owner uid via `ConnectivityManager.getConnectionOwnerUid`
  (Android 10+, VPN owner only) → package (`AppNames`) → `DnsFilter.decide` →
  blocked answer, or cache / upstream. CNAME uncloaking: if any CNAME in an allowed
  answer is blocked, the answer becomes a blocked one (`BLOCKED_CNAME`). Upstream
  0.0.0.0 answers are logged as `BLOCKED_UPSTREAM`.
- Rule order (`Filter.kt`): app allow > app block > global allow > global block >
  list exceptions (`@@`) > lists. User rules cover subdomains.
- Foreground `specialUse` service, `START_STICKY`, Always-on VPN supported
  (`SUPPORTS_ALWAYS_ON`), `BootReceiver` restarts it when `enabled`, `onRevoke`
  turns `enabled` off. Notification shows today's counts (`TodayStats`), tick 15 s.

## Blocklists (`Prefs.kt`, `Blocklist.kt`)

- `ListCatalog`: HaGeZi Pro++, OISD Big, AdGuard DNS filter, HaGeZi DoH bypass on by
  default; the phone brand's HaGeZi native list on by default (`Build.MANUFACTURER`);
  StevenBlack, HaGeZi TIF (1.5 M domains), TikTok off. URLs checked 2026-11-11.
- `ListManager` (one per process, `ListManager.get`): downloads to `files/lists/`,
  stale after 3 days, failed downloads keep the last copy, compiles into
  `files/compiled.bin`.
- `RuleParser`: hosts lines → exact; plain domain lines → exact; `||x^`, `.x^` →
  domain + subdomains; `@@` → exception; `*` and `||prefix.` → wildcard (one joined
  regex); regex rules and rules with modifiers other than `$important` are skipped.
- `Blocklist`: sorted 64-bit FNV-1a hashes (exact / suffix / allow), binary search
  per label suffix. ~8 bytes per domain.

## Code layout

- `android/app/src/main/kotlin/com/itsash/netshield/`
  - Pure (JVM unit tested in `android/app/src/test/.../CoreTest.kt`, `make test-native`):
    `DnsMessage.kt`, `Packets.kt`, `Blocklist.kt`, `Filter.kt` (`Verdict`, `UserRules`,
    `DnsFilter`, `QueryLog`, `DnsCache`), `Upstream.kt`.
  - Android: `ShieldVpnService.kt`, `Prefs.kt` (`ShieldPrefs`, `TodayStats`,
    `ListCatalog`, `ListManager`, `AppNames`), `SystemHooks.kt` (`BootReceiver`,
    `ShieldTileService`), `MainActivity.kt` (MethodChannel `com.itsash.netshield/shield`).
- `lib/shield/shield_platform.dart`: models + channel. `Verdict` indexes must match
  `Verdict` in `Filter.kt`; `Upstream` keys must match `UpstreamProvider`.
- `lib/shield/shield_store.dart`: polls status + log every 2 s while a screen
  `watch()`es it.
- `lib/screens/`: home (toggle, warnings, stats), log, apps + app detail (bypass,
  app rules, top domains), lists, rules, settings, bypass picker.

## Commands

- `make run`, `make build`, `make test` (analyze + Dart tests), `make test-native`
  (Kotlin unit tests, needs one build first), `make clean`.
- Icon: `assets/icon/*.svg` → `rsvg-convert -w 1024 -h 1024` to `*-1024.png`, then
  `dart run flutter_launcher_icons`. Status bar / tile icon:
  `android/app/src/main/res/drawable/ic_stat_shield.xml`.

## Known limits

- Same-domain ads (YouTube, Instagram, Facebook) cannot be blocked by DNS.
- Private DNS set to a hostname bypasses the VPN's DNS: the home screen warns.
- Per-app attribution needs Android 10+. Queries Android's resolver makes for
  itself show as uid 1051 ("Android DNS resolver").
- Not yet tested on a real device: verify per-app attribution and the
  hardcoded-resolver reset path on hardware.

## Conventions

- minSdk 26. UI only from `../theme` (read `../theme/COMPONENTS.md`).
- Network use: DoH upstream, blocklist downloads, `UiUpdateSection`. No analytics.

## Release (Ash Store)

- `store.json` (id `netshield`, repo its-ash/netshield), `store.mk`, `index.html` +
  `CNAME` (`netshield.itsash.in`). See `../ash-store/store-kit/STORE.md`.
- `make deploy` = bump version → build → commit, tag `vX.Y.Z`, push → GitHub
  release with `netshield.apk` → topics, homepage, Pages. Never create releases,
  tags or asset names by hand.
- Do not edit `store.mk` here. Edit `../ash-store/store-kit/store.mk`, then run
  `make store-sync` at the workspace root.
