package com.seef.util.paymentgateway;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.SignatureException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class PaymentGatewayUtil {

	private final static String HMAC_SHA256_ALGORITHM = "HmacSHA256";

	private final static Charset C_UTF8 = Charset.forName("UTF8");

	private static final String ALGO = "AES";

	public static String signingData(List<String> list) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < list.size(); i++) {
			if (i == list.size() - 1)
				sb.append(escapeVal(list.get(i).toString()));
			else
				sb.append(escapeVal(list.get(i).toString()) + ":");
		}
		return sb.toString();

	}

	// To escape embedded "\" characters as "\\", and embedded ":" as "\:".
	public static String escapeVal(String val) {
		if (val == null) {
			return "";
		}
		return val.replace("\\", "\\\\").replace(":", "\\:");
	}

	// To calculate the HMAC SHA-256
	public static String calculateHMAC(String data, byte[] key) throws java.security.SignatureException {
		try {

			// Create an hmac_sha256 key from the raw key bytes
			SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA256_ALGORITHM);

			// Get an hmac_sha256 Mac instance and initialize with the signing
			// key
			Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);

			mac.init(signingKey);

			// Compute the hmac on input data bytes
			byte[] rawHmac = mac.doFinal(data.getBytes(C_UTF8));

			// Base64-encode the hmac
			return Base64.encodeBase64String(rawHmac);

		} catch (Exception e) {
			throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
		}
	}

	/**
	 * Encrypt a string with AES algorithm.
	 *
	 * @param data
	 *            is a string
	 * @return the encrypted string
	 */
	public static String encrypt(String data, String salt) throws Exception {
		Key key = generateKey(salt);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(data.getBytes());
		return Base64.encodeBase64String(encVal);
	}

	/**
	 * Decrypt a string with AES algorithm.
	 *
	 * @param encryptedData
	 *            is a string
	 * @return the decrypted string
	 */
	public static String decrypt(String encryptedData, String salt) throws Exception {
		Key key = generateKey(salt);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = Base64.decodeBase64(encryptedData);
		byte[] decValue = c.doFinal(decordedValue);
		return new String(decValue);
	}

	/**
	 * Generate a new encryption key.
	 */
	private static Key generateKey(String salt) throws Exception {
		return new SecretKeySpec(salt.getBytes("UTF-8"), ALGO);
	}

}
