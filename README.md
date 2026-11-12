# NetShield

Block ads, trackers and malware in every app with a private on-phone DNS filter.

**[Website](https://netshield.itsash.in)** · **[Download APK](https://github.com/its-ash/netshield/releases/latest/download/netshield.apk)** · Get it in **[Ash Store](https://store.itsash.in)**

## Features

- **Whole-phone blocking**: ads, trackers, telemetry and malware are blocked in every app and browser.
- **DNS-only local VPN**: only DNS requests go through NetShield, so speed and battery are not affected and nothing is sent to a VPN server.
- **Strong lists, on by default**: HaGeZi Multi Pro++, OISD Big, AdGuard DNS filter and an encrypted-DNS bypass list. Your phone brand's telemetry list (Xiaomi, Samsung, OPPO/Realme/OnePlus, vivo, Huawei) is turned on automatically. Lists update every 3 days.
- **Hidden trackers caught**: a site that hides a tracker behind its own name (CNAME cloaking) is blocked too.
- **No sneaking around it**: DNS sent straight to Google, Cloudflare, Quad9, AdGuard and other public servers is filtered, and their encrypted DNS is stopped so apps fall back to NetShield.
- **Query log per app**: see every request with the app that made it (Android 10+). Tap one to block or allow it everywhere, or only in that app.
- **Your rules win**: always-block and always-allow lists, plus rules for a single app.
- **Skip an app**: apps that break (some banking apps) can go around NetShield.
- **Encrypted upstream**: allowed requests go out over DNS-over-HTTPS to AdGuard DNS (default), Cloudflare, Quad9 or Google.
- **Home-screen widget**: protection state, requests blocked today and an On/Off button.
- **Quick Settings tile**, start after reboot, and Android's Always-on VPN.

## What it cannot block

- Ads served from the same domain as the content, such as YouTube, Instagram and Facebook ads. Blocking those domains would break the app itself.
- Anything while Android's **Private DNS** is set to a named provider. Set it to Off or Automatic; NetShield warns you when it is not.
- Only one VPN app can run at a time, so NetShield cannot run next to another VPN.

## Install

- **Ash Store**: install [Ash Store](https://store.itsash.in) once, then install and update NetShield from it.
- **APK**: download the [latest APK](https://github.com/its-ash/netshield/releases/latest/download/netshield.apk) on your phone and open it. Allow your browser to install unknown apps if Android asks.

Requires Android 8.0 or newer. Showing the app behind each request needs Android 10 or newer.

## Develop

Needs Flutter ≥ 3.44 and the shared theme package at `../theme`.

```bash
make run          # run on a connected device
make build        # release APK
make test         # flutter analyze + Dart tests
make test-native  # Kotlin unit tests (DNS, packets, lists, rules)
make deploy       # bump version, build, tag, push, GitHub release (see store.mk)
```

## Release

`make deploy` follows the Ash Store kit (`store.mk`, `store.json`): it bumps the
version in `pubspec.yaml`, builds, commits, tags `vX.Y.Z`, pushes, and publishes
a GitHub release with `netshield.apk`. Ash Store and the website pick up the new
version from that release.

## Project layout

```
android/app/src/main/kotlin/com/itsash/netshield/
  ShieldVpnService.kt   DNS-only VPN: tunnel, filtering, upstream, notification
  DnsMessage.kt         DNS wire format (queries, blocked answers, CNAME chains)
  Packets.kt            IPv4/IPv6 UDP replies and TCP resets
  Blocklist.kt          list parser (hosts, domains, adblock) and hashed matcher
  Filter.kt             rule order, query log, DNS cache
  Upstream.kt           DNS-over-HTTPS with plain DNS fallback
  Prefs.kt              settings, list catalog and downloader, app names
  SystemHooks.kt        boot receiver, Quick Settings tile
  MainActivity.kt       MethodChannel for the Flutter UI
lib/
  shield/               channel wrapper, models, store
  screens/              home, log, apps, lists, rules, settings, skip apps
  widgets/              log row with block/allow actions, app icon
```

## License

No license file is included yet.

Built by [itsash.in](https://itsash.in).
