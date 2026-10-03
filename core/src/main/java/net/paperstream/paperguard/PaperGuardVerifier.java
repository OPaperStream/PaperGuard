/*
 * Copyright (c) 2026 LucasTHCR
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */

package net.paperstream.paperguard;

import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Checks PaperGuard logins on a backend: signature, age and replays. Thread safe.
 */
public final class PaperGuardVerifier {

  /** Why a login was accepted or rejected. */
  public enum Result {
    /** Valid, fresh and seen for the first time. */
    OK,
    /** No PaperGuard property. */
    MISSING,
    /** The property is broken or present twice. */
    MALFORMED,
    /** Wrong key, wrong server or modified data. */
    BAD_SIGNATURE,
    /** Older or newer than the allowed age. */
    EXPIRED,
    /** The nonce was already used. */
    REPLAYED
  }

  private final byte[] key;
  private final String serverName;
  private final long maxAgeSeconds;
  /** Nonce to expiry (unix seconds). */
  private final Map<String, Long> seen = new ConcurrentHashMap<>();

  /**
   * Creates a verifier for one server.
   *
   * @param key the server key from {@link PaperGuard#serverKey(byte[], String)}
   * @param serverName this server's name on the proxy
   * @param maxAgeSeconds how long a signed login stays valid
   */
  public PaperGuardVerifier(final byte[] key, final String serverName, final long maxAgeSeconds) {
    this.key = key.clone();
    this.serverName = serverName;
    this.maxAgeSeconds = Math.max(1, maxAgeSeconds);
  }

  /**
   * Verifies one login.
   *
   * @param host host field of the handshake
   * @param ip player IP field
   * @param undashedUuid UUID field
   * @param properties all properties including the PaperGuard one
   * @param nowSeconds the current unix time
   * @return the result
   */
  public Result verify(final String host, final String ip, final String undashedUuid,
                       final List<Property> properties, final long nowSeconds) {
    String value = null;
    for (final Property property : properties) {
      if (PaperGuard.PROPERTY.equals(property.name())) {
        if (value != null) {
          return Result.MALFORMED;
        }
        value = property.value();
      }
    }
    if (value == null) {
      return Result.MISSING;
    }
    final String[] parts = value.split(":", -1);
    if (parts.length != 4 || !PaperGuard.VERSION.equals(parts[0]) || parts[2].isEmpty()) {
      return Result.MALFORMED;
    }
    final long timestamp;
    try {
      timestamp = Long.parseLong(parts[1]);
      Base64.getUrlDecoder().decode(parts[3]);
    } catch (final IllegalArgumentException e) {
      return Result.MALFORMED;
    }
    if (!PaperGuard.verifySignature(key, serverName, value, host, ip, undashedUuid,
        properties)) {
      return Result.BAD_SIGNATURE;
    }
    if (Math.abs(nowSeconds - timestamp) > maxAgeSeconds) {
      return Result.EXPIRED;
    }
    cleanup(nowSeconds);
    // putIfAbsent makes the check and the insert one atomic step.
    if (seen.putIfAbsent(parts[2], nowSeconds + 2 * maxAgeSeconds) != null) {
      return Result.REPLAYED;
    }
    return Result.OK;
  }

  private void cleanup(final long nowSeconds) {
    for (final Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext(); ) {
      if (it.next().getValue() < nowSeconds) {
        it.remove();
      }
    }
  }
}
