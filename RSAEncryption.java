package com.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class RSAEncryption {
	private Cipher cipher;
	

	public RSAEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException{
		this.cipher = Cipher.getInstance("RSA");
	}
	
	public PrivateKey getPrivate(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}
	
	public PublicKey getPublic(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		File f = new File(filename);
		byte[] keyBytes = Files.readAllBytes(f.toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public String encryptTextWithPublicKey(String msg, PublicKey key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
	}

	public static String getKey(String filename) throws FileNotFoundException{
		// Read key from file
		StringBuilder strKeyPEM = new StringBuilder();
		BufferedReader br = new BufferedReader(new FileReader(filename));
		String line;
		try {
			while ((line = br.readLine()) != null) {
				strKeyPEM.append(line).append("\n");
			}
		} catch (IOException e) {
			System.out.println("Exception in getKey:: {}");
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				System.out.println("Exception in getKey catch :: {}");
			}
		}
		return strKeyPEM.toString();
	}

	public static PublicKey getPublicKey(String filename) throws GeneralSecurityException, FileNotFoundException {
		String publicKeyPEM = getKey(filename);
		return getPublicKeyFromString(publicKeyPEM);
	}

	public static PublicKey getPublicKeyFromString(String key) throws GeneralSecurityException {
		String publicKeyPEM = key;
		publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
		publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
		byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
		KeyFactory kf = KeyFactory.getInstance("RSA");

		return kf.generatePublic(new X509EncodedKeySpec(encoded));
	}
}
