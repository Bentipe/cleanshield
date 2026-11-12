# Clean Shield

A system-wide **ad, tracker and porn blocker** for Android. It runs as a local, DNS-only VPN: every domain lookup on the phone is checked against ~729,000 blocked domains on the device itself, before anything leaves the phone. Companion to [Focus Guard](https://github.com/Bentipe/focusguard), which protects it from being switched off.

Plain Java, no dependencies, no analytics, no accounts.

## What it blocks

| Layer | Source | Domains |
|---|---|---|
| Ads, trackers, telemetry | [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) | ~225k |
| Porn | HaGeZi NSFW + [OISD NSFW](https://oisd.nl) | ~565k |
| DNS bypass servers (DoH/DoT) | HaGeZi DoH | ~3.5k |
| Second net: malware + adult | Cloudflare for Families (1.1.1.3) upstream | — |

Also:
- **SafeSearch forced** on Google, Bing and DuckDuckGo (and YouTube Restricted Mode), by answering their hostnames with the SafeSearch servers' addresses.
- **Firefox's own DNS-over-HTTPS is switched off** via its canary domain (`use-application-dns.net`), so Firefox can't skip the filter.
- **Hard-coded DNS servers are filtered too.** Apps that query 8.8.8.8, 1.1.1.1, 9.9.9.9, OpenDNS or AdGuard directly get the filtered answer, and other traffic to those addresses (e.g. DoH by IP) is dropped.

Blocked names get `NXDOMAIN` (Chrome shows `DNS_PROBE_FINISHED_NXDOMAIN`). The app screen shows live counts and the last 40 blocked domains.

## How it works

```
app ──DNS──▶ 10.111.222.53 (inside the VPN tunnel) ──▶ Clean Shield
                                                         ├─ in blocklist?  → NXDOMAIN
                                                         ├─ search engine? → SafeSearch IP
                                                         └─ otherwise      → HTTPS (DoH) to 1.1.1.3 → answer
app ──everything else──▶ normal network (never enters the tunnel)
```

- Only DNS goes through the tunnel, so browsing speed and battery are unaffected and no traffic is proxied.
- Forwarded lookups are encrypted (DNS-over-HTTPS straight to Cloudflare's IP), so your ISP or Wi-Fi owner can't see them.
- The blocklists are compiled at build time into a sorted table of 64-bit hashes (`assets/blocklist.bin`, ~5.8 MB), and each name is checked along with its parent domains with a binary search.

## Limits

- **One VPN at a time.** Android allows a single VPN. Turning on Tailscale, WireGuard, Proton VPN or FortiClient switches Clean Shield off. Afterwards, open Clean Shield and tap **Turn on protection** (always-on also brings it back after a reboot).
- **Never enable "Block connections without VPN"** (*Bloquear conexiones sin VPN*). Clean Shield only carries DNS, so with that switch on, every connection is refused.
- **DNS-level only.** Ads served from the same domain as the content (e.g. YouTube video ads, sponsored posts) can't be blocked by DNS.
- Some apps' "deals" or click-tracking links stop working, because the tracking domain is blocked.

## Build

Requires a JDK, Python 3 and an Android SDK with `build-tools/36.0.0` and `platforms/android-36`.

```bash
./build.sh               # downloads fresh blocklists, builds build/cleanshield.apk
./build.sh --keep-lists  # reuse the last downloaded lists
```

Rebuild every few weeks to refresh the lists. Lists and the signing keystore are git-ignored.

To allow a domain that breaks something, add it to `ALLOW` in [`Filter.java`](src/app/cleanshield/Filter.java) and rebuild.

## Install & activate

```bash
adb install -t -r build/cleanshield.apk
```

On the phone:
1. Open **Clean Shield** → **Turn on protection** → *Aceptar*.
2. **Make it always-on** → ⚙️ next to *Clean Shield* → turn on **VPN siempre activada**. Leave **Bloquear conexiones sin VPN** off.

Then (re)install Focus Guard so its protection covers Clean Shield. Do step 2 first, because Focus Guard blocks Clean Shield's VPN settings page.

## Protection (via Focus Guard)

With Focus Guard active, these are blocked on the phone:
- Clean Shield's App info page (uninstall / force stop / clear storage) and its uninstall dialog.
- Clean Shield's VPN settings page (always-on switch, *Olvidar VPN*).
- The *Desconectar* (disconnect) button in the VPN dialog. The VPN permission prompt still works.
- Android's **Private DNS** dialog, which would otherwise let lookups bypass the filter.

## Uninstall

From a computer:

```bash
adb shell settings put secure always_on_vpn_app null
```
```bash
adb uninstall app.cleanshield
```

If Focus Guard is still installed, its protection doesn't stop adb, only on-phone screens.

## Tested on Pixel 8 / Android 17 (2026-11-12)

| Check | Result |
|---|---|
| wikipedia.org, kaytek.es, Google search in Chrome | work |
| googleads.g.doubleclick.net, app-measurement.com, pagead2.googlesyndication.com, scorecardresearch, demdex, amazon-adsystem | blocked |
| pornhub.com, xvideos.com | blocked (`NXDOMAIN`) |
| www.google.es / www.bing.com | answered with SafeSearch servers |
| dns.google, use-application-dns.net | blocked |
| elpais.com front page | 56% of all lookups blocked, page loads |
| Clean Shield App info, VPN settings page, *Desconectar* dialog, Private DNS dialog | closed by Focus Guard |
