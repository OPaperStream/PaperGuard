/*
 * Copyright (c) 2026 LucasTHCR
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */

package net.paperstream.paperguard;

/**
 * One profile property, as in the legacy forwarding JSON.
 */
public final class Property {

  private final String name;
  private final String value;
  private final String signature;

  /**
   * Creates a property.
   *
   * @param name the name
   * @param value the value
   * @param signature the Mojang signature, may be null or empty
   */
  public Property(final String name, final String value, final String signature) {
    this.name = name;
    this.value = value;
    this.signature = signature == null ? "" : signature;
  }

  /**
   * Returns the name.
   *
   * @return the name
   */
  public String name() {
    return name;
  }

  /**
   * Returns the value.
   *
   * @return the value
   */
  public String value() {
    return value;
  }

  /**
   * Returns the signature.
   *
   * @return the signature, empty if there is none
   */
  public String signature() {
    return signature;
  }
}
