/*
 * Copyright (c) 2026 LucasTHCR
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */

package net.paperstream.paperguard;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Every attack on a signed login must be rejected.
 */
class PaperGuardAttackTest {

  private static final byte[] MASTER = "0123456789abcdef0123456789abcdef".getBytes(
      StandardCharsets.US_ASCII);
  private static final long NOW = 1_800_000_000L;
  private static final String HOST = "play.example.net";
  private static final String IP = "203.0.113.7";
  private static final String UUID = "f3d28cb072253cb1baeb2dadd2be89ae";

  private byte[] lobbyKey;
  private PaperGuardVerifier lobby;
  private int nonceCounter;

  @BeforeEach
  void setUp() {
    lobbyKey = PaperGuard.serverKey(MASTER, "lobby");
    lobby = new PaperGuardVerifier(lobbyKey, "lobby", 10);
  }

  private List<Property> profile() {
    final List<Property> properties = new ArrayList<>();
    properties.add(new Property("textures", "skin-data", "mojang-signature"));
    return properties;
  }

  private String sign(final byte[] key, final String server, final long time, final String host,
                      final String ip, final String uuid) {
    final byte[] nonce = new byte[16];
    nonce[0] = (byte) ++nonceCounter;
    return PaperGuard.sign(key, server, time, nonce, host, ip, uuid, profile());
  }

  private static List<Property> backendProperties(final String paperguard) {
    final List<Property> properties = new ArrayList<>();
    properties.add(new Property("textures", "skin-data", "mojang-signature"));
    if (paperguard != null) {
      properties.add(new Property(PaperGuard.PROPERTY, paperguard, ""));
    }
    return properties;
  }

  @Test
  void validLoginIsAccepted() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.OK,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW));
  }

  @Test
  void replayIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.OK,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW));
    assertEquals(PaperGuardVerifier.Result.REPLAYED,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW + 1));
  }

  @Test
  void tamperedIpIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, "198.51.100.1", UUID, backendProperties(value), NOW));
  }

  @Test
  void tamperedUuidIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, "00000000000000000000000000000001", backendProperties(value), NOW));
  }

  @Test
  void tamperedHostIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify("evil.example.net", IP, UUID, backendProperties(value), NOW));
  }

  @Test
  void tamperedPropertiesAreRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    final List<Property> properties = new ArrayList<>();
    properties.add(new Property("textures", "other-skin", "mojang-signature"));
    properties.add(new Property(PaperGuard.PROPERTY, value, ""));
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, UUID, properties, NOW));
  }

  @Test
  void addedPropertyIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    final List<Property> properties = backendProperties(value);
    properties.add(new Property("injected", "x", ""));
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, UUID, properties, NOW));
  }

  @Test
  void loginForAnotherServerIsRejected() {
    final byte[] survivalKey = PaperGuard.serverKey(MASTER, "survival");
    final String forSurvival = sign(survivalKey, "survival", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, UUID, backendProperties(forSurvival), NOW));
    // Even a leaked lobby key cannot sign for another server name and pass on lobby.
    final String renamed = sign(lobbyKey, "survival", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, UUID, backendProperties(renamed), NOW));
  }

  @Test
  void wrongSecretIsRejected() {
    final byte[] other = PaperGuard.serverKey(
        "ffffffffffffffffffffffffffffffff".getBytes(StandardCharsets.US_ASCII), "lobby");
    final String value = sign(other, "lobby", NOW, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.BAD_SIGNATURE,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW));
  }

  @Test
  void oldLoginIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW - 11, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.EXPIRED,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW));
  }

  @Test
  void loginFromTheFutureIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW + 11, HOST, IP, UUID);
    assertEquals(PaperGuardVerifier.Result.EXPIRED,
        lobby.verify(HOST, IP, UUID, backendProperties(value), NOW));
  }

  @Test
  void missingSignatureIsRejected() {
    assertEquals(PaperGuardVerifier.Result.MISSING,
        lobby.verify(HOST, IP, UUID, backendProperties(null), NOW));
  }

  @Test
  void malformedSignaturesAreRejected() {
    for (final String bad : new String[] {"", "v1", "v1:1:2", "v2:1:abc:def", "v1:x:abc:def",
        "v1:1::def", "v1:1:abc:!!!", "v1:1:abc:def:extra"}) {
      final PaperGuardVerifier.Result result =
          lobby.verify(HOST, IP, UUID, backendProperties(bad), NOW);
      assertEquals(true, result == PaperGuardVerifier.Result.MALFORMED
          || result == PaperGuardVerifier.Result.BAD_SIGNATURE, bad + " -> " + result);
    }
  }

  @Test
  void duplicatePaperGuardPropertyIsRejected() {
    final String value = sign(lobbyKey, "lobby", NOW, HOST, IP, UUID);
    final List<Property> properties = backendProperties(value);
    properties.add(new Property(PaperGuard.PROPERTY, value, ""));
    assertEquals(PaperGuardVerifier.Result.MALFORMED,
        lobby.verify(HOST, IP, UUID, properties, NOW));
  }
}
