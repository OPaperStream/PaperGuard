# PaperGuard protocol, version 1

PaperGuard adds a signature to BungeeCord ("legacy") IP forwarding, so a backend can prove that
a login really comes from its proxy. Without it, anyone who reaches the backend port can join
with any name and UUID.

## Keys

The proxy has one random master secret (at least 32 bytes). Every backend gets its own key:

```
serverKey = HMAC-SHA256(masterSecret, UTF-8("paperproxy-paperguard-v1:" + lowercase(serverName)))
```

`serverName` is the name of the server on the proxy. A backend only knows its own key, so a
leaked key cannot be used against other servers. The key is shared as standard Base64.

## Handshake

Legacy forwarding sends the handshake host field as `host\0ip\0uuid\0propertiesJson`, where
`uuid` has no dashes and `propertiesJson` is the profile property list
(`[{"name":..,"value":..,"signature":..}]`).

PaperGuard appends one property to that list:

```
{"name": "paperguard", "value": "v1:<timestamp>:<nonce>:<signature>"}
```

- `timestamp`: unix time in seconds
- `nonce`: 16 random bytes, Base64url without padding, never reused
- `signature`: `HMAC-SHA256(serverKey, payload)`, Base64url without padding

`payload` is the UTF-8 encoding of:

```
"v1" \n
lowercase(serverName) \n
timestamp \n
nonce \n
host \n
ip \n
lowercase(uuid) \n
for every property except "paperguard", in the order sent:
  name \0 value \0 signature-or-empty \n
```

## Verification on the backend

A backend must reject the login unless all of this holds:

1. Exactly one `paperguard` property is present and has four `:` separated parts, the first
   being `v1`.
2. The signature matches (compare in constant time) for this server's name and key.
3. `|now - timestamp|` is at most the allowed age (default 10 seconds).
4. The nonce was not seen within the last 2 x allowed age.

The `paperguard` property is removed before the profile is used. If the backend is not
configured, it must reject every login (fail closed).

## Test vectors

[`test-vectors.json`](test-vectors.json) lists inputs with the expected server key and
property value. They were computed with an independent implementation; every implementation
should reproduce them exactly.
