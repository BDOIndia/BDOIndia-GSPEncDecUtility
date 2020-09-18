package com.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class AESEncryption {
	public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
	public static final String AES_ALGORITHM = "AES";
	public static final int ENC_BITS = 256;
	public static final String CHARACTER_ENCODING = "UTF-8";

	private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	public static final String EXCEPTION = "Exception :: {}";
	

	private AESEncryption() {
		
	}
	static{
		try{
			encryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			decryptCipher = Cipher.getInstance(AES_TRANSFORMATION);
			
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {			
			System.out.println(e.getMessage());
		}
	}


	public static String encodeBase64String(byte[] bytes) {
		return new String(java.util.Base64.getEncoder().encode(bytes));
	}

	public static byte[] decodeBase64StringTOByte(String stringData) {
		return java.util.Base64.getDecoder().decode(stringData.getBytes(StandardCharsets.UTF_8));
	}



	public static String encryptEK(byte[] plainText, byte[] secret){
		try{

			SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, sk);
			return Base64.getEncoder().encodeToString(encryptCipher
					.doFinal(plainText));

		}catch(Exception e){
			System.out.println(e.getMessage());
			return "";
		}
	}


	public static byte[] decrypt(String plainText, byte[] secret) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);		
		return decryptCipher.doFinal(Base64.getDecoder().decode(plainText));
	}

	public static byte[] decryptCred(String plainText, byte[] secret)throws InvalidKeyException, IllegalBlockSizeException,BadPaddingException, UnsupportedEncodingException {
		SecretKeySpec sk = new SecretKeySpec(secret, AES_ALGORITHM);
		decryptCipher.init(Cipher.DECRYPT_MODE, sk);		
		return decryptCipher.doFinal(plainText.getBytes("UTF-8"));
	}
}
