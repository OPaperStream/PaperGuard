<p align="center"><img src="assets/icon-256.png" width="160"></p>

# PaperGuard

Signed, replay-proof IP forwarding for Minecraft servers behind a proxy.

> **NOT AN OFFICIAL PAPER PROJECT.** PaperGuard is not affiliated with or endorsed by PaperMC.

## Why?

Old servers and many plugins only work with BungeeCord ("legacy") forwarding. That forwarding
has no protection at all: whoever reaches the backend port can join with any name and UUID,
including your admins. Firewalls and BungeeGuard help, but a single shared token can be
sniffed or leaked and then used forever, on every server.

PaperGuard signs every login instead:

- **Signed per login.** HMAC-SHA256 over name, UUID, IP, host, skin data, target server and
  time. Change one byte and the login is rejected.
- **Replay-proof.** Every login has a one-time nonce and is only valid for a few seconds.
  A recorded login cannot be used again.
- **One key per server.** A leaked key from one backend does not open the others.
- **Fail closed.** If PaperGuard is not set up, nobody can join, instead of everybody.
- **Old servers too.** Paper 1.12.2 and newer, Folia, Java 8+.

## Download

[Modrinth](https://modrinth.com/plugin/paperguard) (in review) · [Hangar](https://hangar.papermc.io/LucasTHCR/PaperGuard) · [GitHub releases](https://github.com/OPaperStream/PaperGuard/releases)

## Setup with PaperProxy

[PaperProxy](https://github.com/OPaperStream/PaperProxy) signs logins out of the box.

1. In `paperproxy.toml` on the proxy, set the server to PaperGuard:
   ```toml
   [forwarding.servers]
   survival = "paperguard"
   ```
2. In the proxy console run `paperproxy paperguard key survival`.
3. Put `PaperGuard-<version>.jar` into the backend's `plugins/` folder and start it once.
4. Enter `server-name` and `key` in `plugins/PaperGuard/config.yml`, set
   `settings.bungeecord: true` in `spigot.yml` and restart.

Players joining through the proxy get in, everyone connecting directly is kicked.

Coming from **PaperProxy-Bridge**? That was the old name of this plugin. Replace the jar, your
settings are taken over automatically.

## For other proxies

The format is small and documented in [SPEC.md](SPEC.md), with
[test vectors](test-vectors.json). The `core` module (`paperguard-core`, MIT, no
dependencies, Java 8) signs and verifies:

```java
byte[] key = PaperGuard.serverKey(masterSecret, "survival");
String value = PaperGuard.sign(key, "survival", nowSeconds, nonce, host, ip, uuid, properties);
// add {"name":"paperguard","value":value} to the forwarded properties
```

## Building

```bash
./gradlew build
```

The plugin is `paper/build/libs/PaperGuard-<version>.jar`, the library
`core/build/libs/paperguard-core-<version>.jar`.

## License

MIT, see [LICENSE](LICENSE). Made by LucasTHCR. Questions:
[Discord](https://dc.gg/paperstream)
