/*
 * Copyright (c) 2026 LucasTHCR
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */

package net.paperstream.paperguard.paper;

import com.destroystokyo.paper.event.player.PlayerHandshakeEvent;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import net.paperstream.paperguard.PaperGuard;
import net.paperstream.paperguard.PaperGuardVerifier;
import net.paperstream.paperguard.Property;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * PaperGuard for Paper: verifies signed logins from the proxy and tells PaperProxy about
 * this server.
 *
 * <p>Fail-closed: when the bridge is not configured correctly, nobody can join.
 */
public final class PaperGuardPlugin extends JavaPlugin implements Listener {

  static final String CHANNEL = "paperproxy:bridge";
  private static final String REJECT = "Unable to verify your connection. Please join through "
      + "the server's proxy.";

  private volatile PaperGuardVerifier verifier;
  private volatile String setupProblem;
  private Set<String> allowedProxies = new HashSet<>();
  private Method originalSocketAddress;
  private final AtomicBoolean reported = new AtomicBoolean();

  @Override
  public void onEnable() {
    migrateBridgeConfig();
    saveDefaultConfig();
    setupProblem = configure();
    if (setupProblem != null) {
      getLogger().severe("==============================================================");
      getLogger().severe("PaperGuard is NOT active: " + setupProblem);
      getLogger().severe("For safety every login is rejected until this is fixed.");
      getLogger().severe("==============================================================");
    } else {
      getLogger().info("PaperGuard active for server '" + getConfig().getString("server-name")
          + "'.");
    }
    try {
      originalSocketAddress = PlayerHandshakeEvent.class
          .getMethod("getOriginalSocketAddressHostname");
    } catch (final NoSuchMethodException e) {
      originalSocketAddress = null;
      if (!allowedProxies.isEmpty()) {
        getLogger().warning("allowed-proxy-addresses needs Paper 1.16.5 or newer and is ignored.");
      }
    }
    getServer().getMessenger().registerOutgoingPluginChannel(this, CHANNEL);
    getServer().getPluginManager().registerEvents(this, this);
  }

  /** Takes over the config of PaperProxy-Bridge, the old name of this plugin. */
  private void migrateBridgeConfig() {
    final File own = new File(getDataFolder(), "config.yml");
    final File old = new File(getDataFolder().getParentFile(),
        "PaperProxy-Bridge/config.yml");
    if (own.exists() || !old.isFile()) {
      return;
    }
    try {
      getDataFolder().mkdirs();
      Files.copy(old.toPath(), own.toPath());
      getLogger().info("Took over the settings of PaperProxy-Bridge. You can remove that "
          + "plugin and its folder now.");
      reloadConfig();
    } catch (final IOException e) {
      getLogger().log(Level.WARNING, "Could not take over the PaperProxy-Bridge config", e);
    }
  }

  private String configure() {
    if (!Bukkit.spigot().getConfig().getBoolean("settings.bungeecord", false)) {
      return "settings.bungeecord is false in spigot.yml";
    }
    final String serverName = getConfig().getString("server-name", "").trim();
    if (serverName.isEmpty()) {
      return "server-name is empty in plugins/PaperGuard/config.yml";
    }
    final byte[] key;
    try {
      key = Base64.getDecoder().decode(getConfig().getString("key", "").trim());
    } catch (final IllegalArgumentException e) {
      return "key is not valid Base64";
    }
    if (key.length != 32) {
      return "key is missing or incomplete; run 'paperproxy paperguard key " + serverName
          + "' on the proxy";
    }
    final long maxAge = Math.max(1, getConfig().getLong("max-age-seconds", 10));
    allowedProxies = new HashSet<>(getConfig().getStringList("allowed-proxy-addresses"));
    verifier = new PaperGuardVerifier(key, serverName, maxAge);
    return null;
  }

  /**
   * Verifies the forwarded handshake before Paper uses it.
   *
   * @param event the event
   */
  @EventHandler(priority = EventPriority.LOWEST)
  public void onHandshake(final PlayerHandshakeEvent event) {
    // Handling the event (not cancelled) makes Paper use exactly what we set below.
    event.setCancelled(false);
    final PaperGuardVerifier current = verifier;
    if (current == null) {
      fail(event, "bridge not configured");
      return;
    }
    if (!allowedProxies.isEmpty() && originalSocketAddress != null) {
      try {
        final Object address = originalSocketAddress.invoke(event);
        if (!allowedProxies.contains(String.valueOf(address))) {
          fail(event, "connection from " + address + " which is not an allowed proxy address");
          return;
        }
      } catch (final ReflectiveOperationException e) {
        fail(event, "could not read the connection address");
        return;
      }
    }

    final String[] split = event.getOriginalHandshake().split("\0", -1);
    if (split.length != 4) {
      fail(event, "not forwarded by PaperProxy");
      return;
    }
    final List<Property> properties = new ArrayList<>();
    final JsonArray kept = new JsonArray();
    try {
      final JsonElement parsed = new JsonParser().parse(split[3]);
      for (final JsonElement element : parsed.getAsJsonArray()) {
        final JsonObject object = element.getAsJsonObject();
        final String name = object.get("name").getAsString();
        final String value = object.get("value").getAsString();
        final String signature = object.has("signature") ? object.get("signature").getAsString()
            : "";
        properties.add(new Property(name, value, signature));
        if (!PaperGuard.PROPERTY.equals(name)) {
          kept.add(object);
        }
      }
    } catch (final RuntimeException e) {
      fail(event, "malformed forwarding data");
      return;
    }

    final PaperGuardVerifier.Result result = current.verify(split[0], split[1], split[2],
        properties, System.currentTimeMillis() / 1000L);
    if (result != PaperGuardVerifier.Result.OK) {
      fail(event, "PaperGuard " + result.name().toLowerCase(Locale.ROOT).replace('_', ' ')
          + " (player IP " + split[1] + ")");
      return;
    }
    event.setServerHostname(split[0]);
    event.setSocketAddressHostname(split[1]);
    event.setUniqueId(uuid(split[2]));
    event.setPropertiesJson(new Gson().toJson(kept));
  }

  /**
   * Second safety net: if the handshake check could not run (misconfiguration), refuse logins.
   *
   * @param event the event
   */
  @EventHandler(priority = EventPriority.LOWEST)
  public void onPreLogin(final AsyncPlayerPreLoginEvent event) {
    if (verifier == null) {
      event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, REJECT);
    }
  }

  /**
   * Tells the proxy which bridge version and plugins run here, once per server start.
   *
   * @param event the event
   */
  @EventHandler
  public void onJoin(final PlayerJoinEvent event) {
    if (!reported.compareAndSet(false, true)) {
      return;
    }
    final Map<String, Object> report = new LinkedHashMap<>();
    report.put("bridge", getDescription().getVersion());
    report.put("paperguard", getDescription().getVersion());
    report.put("server", getConfig().getString("server-name", ""));
    report.put("software", Bukkit.getName() + " " + Bukkit.getVersion());
    final List<String> plugins = new ArrayList<>();
    for (final Plugin plugin : Bukkit.getPluginManager().getPlugins()) {
      plugins.add(plugin.getName());
    }
    report.put("plugins", plugins);
    try {
      event.getPlayer().sendPluginMessage(this, CHANNEL,
          new Gson().toJson(report).getBytes(StandardCharsets.UTF_8));
    } catch (final RuntimeException e) {
      reported.set(false);
      getLogger().log(Level.FINE, "Could not send the bridge report", e);
    }
  }

  private void fail(final PlayerHandshakeEvent event, final String reason) {
    getLogger().warning("Rejected a login: " + reason);
    event.setFailed(true);
    event.setFailMessage(REJECT);
  }

  private static UUID uuid(final String undashed) {
    return UUID.fromString(undashed.replaceFirst(
        "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
        "$1-$2-$3-$4-$5"));
  }

  /**
   * For tests: whether the bridge is ready.
   *
   * @return the setup problem, or null
   */
  String setupProblem() {
    return setupProblem;
  }
}
