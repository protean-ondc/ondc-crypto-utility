package ondc.crypto.util;

import static org.junit.jupiter.api.Assertions.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;



public class CryptoTest {
	private final String testCase1="Positive flow of signing and verification";

	@Test
	@DisplayName(testCase1)
	public void testGenerateSigningKeyPair_Normal() {
		System.out.println(testCase1+": Start");
		System.out.println("\n\n\n");
		
		System.out.println("Testing whether Signing Keys are generated::");
		CryptoKeyPair signingKeyPair=CryptoFunctions.generateSigningKeyPair();
		
		
		String message="message to be signed";
		byte[] signature= CryptoFunctions.sign(signingKeyPair.getPrivateKey(), message.getBytes());
		
		System.out.println("\n\n/** Sender Side **/");
		System.out.println("{");
		System.out.println("\t\"message \":\""+message +"\",");
		System.out.println("\t\"signature \":\""+Base64.getEncoder().encodeToString(signature)+"\",");
		System.out.println("\t\"privateKey \":\""+Base64.getEncoder().encodeToString(signingKeyPair.getPrivateKey()) +"\",");
		System.out.println("}\n\n");
		
		
		boolean verificationResult=CryptoFunctions.verify(signature, message.getBytes(), signingKeyPair.getPublickKey());
		
		System.out.println("\n\n/** Receiver Side **/");
		System.out.println("{");
		System.out.println("\t\"message \":\""+message +"\",");
		System.out.println("\t\"signature \":\""+Base64.getEncoder().encodeToString(signature)+"\",");
		System.out.println("\t\"publicKey \":\""+Base64.getEncoder().encodeToString(signingKeyPair.getPublickKey()) +"\",");
		System.out.println("\t\"verified \":\""+verificationResult +"\",");
		System.out.println("}\n\n");
		
		assertEquals(true, verificationResult);
		System.out.println(testCase1+": End with status:"+verificationResult);
		
	}
	
	@Test
	@DisplayName("Negative Flow to check whether tampered message is verified unsuccessfully")
	public void testGenerateSigningKeyPair_Tampered() {
		CryptoKeyPair signingKeyPair=CryptoFunctions.generateSigningKeyPair();
		String message="message to be signed";
		byte[] signature= CryptoFunctions.sign(signingKeyPair.getPrivateKey(), message.getBytes());
		String tamperedMessage="tampered message ";
		assertEquals(false, (CryptoFunctions.verify(signature, tamperedMessage.getBytes(), signingKeyPair.getPublickKey())));
	}
	
	@Test
	@DisplayName("To check normal flow of Encryption and Decryption")
	public void testGenerateEncryptionDecryptionKeyPair_Normal() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		CryptoKeyPair senderEncDecKeyPair=null;
		CryptoKeyPair receiverEncDecKeyPair=null;
		
		try {
			senderEncDecKeyPair= CryptoFunctions.generateEncDecKey();
			receiverEncDecKeyPair= CryptoFunctions.generateEncDecKey();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		String message="message to be encrypted";
		
		byte[] encrypted= CryptoFunctions.encryptDecrypt(Cipher.ENCRYPT_MODE,message.getBytes(),senderEncDecKeyPair.getPrivateKey(),receiverEncDecKeyPair.getPublickKey());
		
		System.out.println("\n\n/** Sender Side **/");
		System.out.println("{");
		System.out.println("\t\"plainChallengeString \":\""+message +"\",");
		System.out.println("\t\"EncryptedChallengeString \":\""+Base64.getEncoder().encodeToString(encrypted)+"\",");
		System.out.println("\t\"senderPrivateKey \":\""+Base64.getEncoder().encodeToString(senderEncDecKeyPair.getPrivateKey()) +"\",");
		System.out.println("\t\"receiverPublicKey \":\""+Base64.getEncoder().encodeToString(receiverEncDecKeyPair.getPublickKey()) +"\"");
		System.out.println("}\n\n");
		
		byte[] decrypted= CryptoFunctions.encryptDecrypt(Cipher.DECRYPT_MODE,encrypted,receiverEncDecKeyPair.getPrivateKey(),senderEncDecKeyPair.getPublickKey());
		String decryptedMessage=new String(decrypted);
		
		System.out.println("\n\n/** Receiver Side **/");
		System.out.println("{");
		System.out.println("\t\"DecryptedChallengeString \":\""+decryptedMessage+"\",");
		System.out.println("\t\"receiverPrivateKey \":\""+Base64.getEncoder().encodeToString(receiverEncDecKeyPair.getPrivateKey()) +"\",");
		System.out.println("\t\"senderPublicKey \":\""+Base64.getEncoder().encodeToString(senderEncDecKeyPair.getPublickKey()) +"\"");
		System.out.println("}");
		

		assertEquals(message, decryptedMessage);
	}



}
