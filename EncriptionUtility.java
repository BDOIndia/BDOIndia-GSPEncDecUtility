package com.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;



public class EncriptionUtility {

	private static final String publicKeyPath="D://Testing/public.key";
	private static final String candidateChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	private static String encryptWithBDOPubKey(String bdoPubKeyPath,String ecryptData) throws Exception{
		PublicKey publicKey = RSAEncryption.getPublicKey(bdoPubKeyPath);
		String encText = new RSAEncryption().encryptTextWithPublicKey(ecryptData, publicKey);
		return encText;
	}
	private static String getAppKey() {
		String appKey = generateRandomChars(candidateChars,32);
		System.out.println("New AppKey : " + appKey + " on :" + LocalDateTime.now());
		return appKey;
	}

	private static String encryptPasswordWithPubKey(String password) {

		String strPublicKeyPath = publicKeyPath;
		PublicKey publicKey = null;
		String encryptedPassword = null;
		try {
			RSAEncryption rsaEncUtil = new RSAEncryption();
			publicKey = rsaEncUtil.getPublic(strPublicKeyPath);
			encryptedPassword = rsaEncUtil.encryptTextWithPublicKey(password, publicKey);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedPassword;
	}

	private static String encryptAppKeyWithPubKey(String appKey) {

		String strPublicKeyPath = publicKeyPath;
		PublicKey publicKey = null;
		String encryptedAppKey = null;
		try {
			RSAEncryption rsaEncUtil = new RSAEncryption();
			publicKey = rsaEncUtil.getPublic(strPublicKeyPath + "/public.key");
			encryptedAppKey = rsaEncUtil.encryptTextWithPublicKey(appKey, publicKey);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return encryptedAppKey;
	}
	
	private static String decryptSEK(String sek,String appKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{

		byte[] appKeyBytes = appKey.getBytes(StandardCharsets.UTF_8);
		byte[] decryptedTextBytes = AESEncryption.decrypt(sek, appKeyBytes);

		return Base64.getEncoder().encodeToString(decryptedTextBytes);
	}
	
	private static String encryptPayload(String jsonToEncrypt, String decryptedSek) {
		byte[] sekByte = Base64.getDecoder().decode(decryptedSek);
		Key aesKey = new SecretKeySpec(sekByte, "AES");
		try {

			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
			byte[] encryptedjsonbytes = cipher.doFinal(jsonToEncrypt.getBytes("UTF-8"));
			String encryptedJson = Base64.getEncoder().encodeToString(encryptedjsonbytes);
			return encryptedJson;
		} catch (Exception e) {
			e.printStackTrace();
			return "Exception " + e;
		}
	}
	public static String decryptResponseData(String encryptedResponseData,String decrypteSEK) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] encKeyBytes = Base64.getDecoder().decode(decrypteSEK);
		byte[] decryptedTextBytes = AESEncryption.decrypt(encryptedResponseData, encKeyBytes);

		return new String(decryptedTextBytes);

	}
	
	public static String generateRandomChars(String candidateChars, int length) {
	    StringBuilder sb = new StringBuilder();
	    Random random = new Random();
	    for (int i = 0; i < length; i++) {
	        sb.append(candidateChars.charAt(random.nextInt(candidateChars
	                .length())));
	    }

	    return sb.toString();
	}
}
