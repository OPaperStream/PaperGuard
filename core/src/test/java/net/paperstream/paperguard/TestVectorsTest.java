/*
 * Copyright (c) 2026 LucasTHCR
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */

package net.paperstream.paperguard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Checks this implementation against test-vectors.json, which was computed independently.
 */
class TestVectorsTest {

  @Test
  void matchesAllVectors() throws IOException {
    final String json = new String(Files.readAllBytes(Paths.get("..", "test-vectors.json")),
        StandardCharsets.UTF_8);
    int checked = 0;
    for (final JsonElement element : JsonParser.parseString(json).getAsJsonObject()
        .getAsJsonArray("vectors")) {
      final JsonObject vector = element.getAsJsonObject();
      final byte[] key = PaperGuard.serverKey(
          vector.get("masterSecret").getAsString().getBytes(StandardCharsets.UTF_8),
          vector.get("serverName").getAsString());
      assertEquals(vector.get("serverKey").getAsString(),
          Base64.getEncoder().encodeToString(key));

      final List<Property> properties = new ArrayList<>();
      for (final JsonElement p : vector.getAsJsonArray("properties")) {
        final JsonObject property = p.getAsJsonObject();
        properties.add(new Property(property.get("name").getAsString(),
            property.get("value").getAsString(),
            property.get("signature").isJsonNull() ? null
                : property.get("signature").getAsString()));
      }
      final String value = PaperGuard.sign(key, vector.get("serverName").getAsString(),
          vector.get("timestamp").getAsLong(), hex(vector.get("nonceHex").getAsString()),
          vector.get("host").getAsString(), vector.get("ip").getAsString(),
          vector.get("uuid").getAsString(), properties);
      assertEquals(vector.get("value").getAsString(), value);
      assertTrue(PaperGuard.verifySignature(key, vector.get("serverName").getAsString(), value,
          vector.get("host").getAsString(), vector.get("ip").getAsString(),
          vector.get("uuid").getAsString(), properties));
      checked++;
    }
    assertEquals(3, checked);
  }

  private static byte[] hex(final String text) {
    final byte[] out = new byte[text.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
    }
    return out;
  }
}
