package ism.ase.ro;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	
	public static String getHex(byte[] values) {
		StringBuilder sb = new StringBuilder();
		for(byte b : values) {
			sb.append(String.format(" %02x", b));
		}
		return sb.toString();
	}
	
	static byte[] getFileSha(String filename) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
		File file = new File(filename);
		if(!file.exists())
			System.out.println("************* The file is not there");
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		MessageDigest md = MessageDigest.getInstance("SHA-256", "SUN");
		byte[] buffer = new byte[8];
		
		do {
			int noBytes = bis.read(buffer); //we try to read 8 bytes
			if(noBytes != -1) {
				md.update(buffer, 0, noBytes);
			} else {break;}
		}while(true);
		
		//get final hash
		byte[] hashValue = md.digest();
		
		bis.close();
		return hashValue;
	}
	
	public static void encrypt(
			String filename, 
			String cipherFilename, 
			String password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV is known/generated and placed in the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(cipherFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//IV has the 5th byte from left to right all bits 1
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[5] = (byte) 0xCC;
		
		SecretKeySpec key = new SecretKeySpec(password.getBytes(), algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		//write the IV in the file
		fos.write(IV);
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = 
				KeyGenerator.getInstance("AES");
		keyGenerator.init(noBytes);
		return keyGenerator.generateKey().getEncoded();
	}
	
	public static KeyStore getKeyStore(
			String keyStoreFile,
			String keyStorePass, 
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		File file = new File(keyStoreFile);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing key store file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		
		KeyStore ks = KeyStore.getInstance(keyStoreType);
		ks.load(fis, keyStorePass.toCharArray());
		
		fis.close();
		return ks;
	}
	
	public static void list(KeyStore ks) throws KeyStoreException {
		System.out.println("Key store content: ");
		Enumeration<String> aliases = ks.aliases();
		
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			System.out.println("Entry: " + alias);
			if(ks.isCertificateEntry(alias)) {
				System.out.println("-- Is a certificate");
			}
			if(ks.isKeyEntry(alias)) {
				System.out.println("-- Is a key pair");
			}
		}
	}
	
	public static PublicKey getPublicKey(String alias, KeyStore ks) throws KeyStoreException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return ks.getCertificate(alias).getPublicKey();
		} else {
			return null;
		}
	}
	
	public static PrivateKey getPrivateKey(
			String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		if(ks == null) {
			throw new UnsupportedOperationException("Missing Key Store");
		}
		if(ks.containsAlias(alias)) {
			return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
		} else {
			return null;
		}
	}
	
	public static PublicKey getCertificateKey(String certificateFile) throws CertificateException, IOException {
		File file = new File(certificateFile);
		if(!file.exists()) {
			throw new UnsupportedOperationException("****Missing file****");
		}
		FileInputStream fis = new FileInputStream(file);
		
		CertificateFactory certFactory = 
				CertificateFactory.getInstance("X.509");
		X509Certificate certificate = 
				(X509Certificate) certFactory.generateCertificate(fis);
		fis.close();
		return certificate.getPublicKey();	
	}
	
	public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		FileInputStream fis = new FileInputStream(file);
		
		byte[] fileContent = fis.readAllBytes();
		
		fis.close();
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		
		signature.update(fileContent);
		return signature.sign();		
	}
	
	public static boolean hasValidSignature(
			String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		
		File file = new File(filename);
		if(!file.exists()) {
			throw new FileNotFoundException();
		}
		
		FileInputStream fis = new FileInputStream(file);	
		byte[] fileContent = fis.readAllBytes();	
		fis.close();
		
		Signature signatureModule = Signature.getInstance("SHA256withRSA");
		signatureModule.initVerify(key);
		
		signatureModule.update(fileContent);
		return signatureModule.verify(signature);
		
	}
	
	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		result.append("0x");
		for(byte b : value) {
			result.append(String.format(" %02X", b));
		}
		return result.toString();
	}
	
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnrecoverableKeyException, KeyStoreException, CertificateException, SignatureException {
		// TODO Auto-generated method stub
		byte[] sha = getFileSha("msg.txt");
		System.out.println(getHex(sha));
		encrypt("msg.txt", "enc_msg.aes", "passwordsecurity", "AES");
		
		KeyStore ks = getKeyStore(
				"ismkeystore.ks", "passks", "pkcs12");
		list(ks);
		
		PublicKey pubIsm1 = getPublicKey("ismkey1", ks);
		PrivateKey privIsm1 = getPrivateKey("ismkey1", "passks", ks);
		
		System.out.println("Public key:");
		System.out.println(getHexString(pubIsm1.getEncoded()));
		System.out.println("Private key");
		System.out.println(getHexString(privIsm1.getEncoded()));
		
		PublicKey pubIsm1FromCert = 
				getCertificateKey("ISMCertificateX509.cer");
		System.out.println("Public key from certificate: ");
		System.out.println(getHexString(pubIsm1FromCert.getEncoded()));
		
		byte[] signature = 
				signFile("enc_msg.aes", privIsm1);
		
		System.out.println("Digital signature value: ");
		System.out.println(getHexString(signature));
		
		if(hasValidSignature(
				"enc_msg.aes", pubIsm1FromCert, signature))
		{
			System.out.println("File is the original one");
		} else {
			System.out.println("File has been changed");
		}
		
		File dataFile = new File("FileSignature.ds");
		if(!dataFile.exists()) {
			dataFile.createNewFile();
		}
		FileOutputStream fos = new FileOutputStream(dataFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		DataOutputStream dos = new DataOutputStream(bos);
		

		dos.write(signature);
		dos.close();
		
	}

}
