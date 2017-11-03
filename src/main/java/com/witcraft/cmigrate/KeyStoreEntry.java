package com.witcraft.cmigrate;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 *
 * @author Jason Redding
 */
public class KeyStoreEntry {
	private final String alias;
	private final Object entry;

	public KeyStoreEntry(String alias, Object entry) {
		this.alias = alias;
		if (!(entry instanceof Certificate || entry instanceof Key)) {
			throw new IllegalArgumentException("entry must be either Certificate or Key");
		}
		this.entry = entry;
	}

	public String getAlias() {
		return alias;
	}

	public Object getEntry() {
		return entry;
	}

	public boolean isX509Certificate() {
		return (entry instanceof X509Certificate);
	}

	public boolean isCertificateEntry() {
		return (entry instanceof Certificate);
	}

	public boolean isKeyEntry() {
		return (entry instanceof Key);
	}

	public X509Certificate getX509Certificate() {
		return (X509Certificate)entry;
	}

	public Certificate getCertificate() {
		return (Certificate)entry;
	}

	public Key getKey() {
		return (Key)entry;
	}

}
