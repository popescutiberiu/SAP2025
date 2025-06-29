package ism.ase.ro;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static byte[] getFileMessageDigest(
			File file, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
		
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		MessageDigest ms = MessageDigest.getInstance(algorithm, provider);
		
		byte[] buffer = new byte[8];
		int noBytesFromFile = 0;
		
		while((noBytesFromFile = bis.read(buffer)) != -1) {
			ms.update(buffer, 0, noBytesFromFile);
		}
		
		bis.close();
		
		return ms.digest();		
	}
	
	
	public static void decrypt(
			String filename, 
			String outputFile, 
			byte[] password, 
			String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		
		//IV the cipher file at the beginning
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File outFile = new File(outputFile);
		if(!outFile.exists()) {
			outFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
		
		//getting the IV from the file
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[15] = 23;
		IV[14] = 20;
		IV[13] = 2;
		IV[12] = 3;
		
		SecretKeySpec key = new SecretKeySpec(password, algorithm);
		IvParameterSpec ivSpec = new IvParameterSpec(IV);
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		
		byte[] buffer = new byte[cipher.getBlockSize()];
		int noBytes = 0;
		
		while(true) {
			noBytes = fis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
			fos.write(cipherBlock);
		}
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
	
	public static byte[] encrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
	
	public static byte[] decrypt(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(input);
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
	
	
	
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException, CertificateException, UnrecoverableKeyException, KeyStoreException {
		// TODO Auto-generated method stub

		
		Map<String, byte[]> mappedFingerprints = new HashMap<>();
		File fingerprints = new File("sha2Fingerprints.txt");
		if(!fingerprints.exists()) {
			System.out.println("fingerprints file not found"); 
		}
		
		FileReader fileReader = new FileReader(fingerprints);
		BufferedReader bufferedReader = new BufferedReader(fileReader);
		
		String line;
		
		while((line = bufferedReader.readLine()) != null) {
			mappedFingerprints.put(line, Base64.getDecoder().decode(bufferedReader.readLine()));
		} 		
		//System.out.println(mappedFingerprints.get("system32\\"+"svchost1.exe"));
		
		bufferedReader.close();
		
		File location = new File("system32");
		if(!location.exists()) {
			throw new UnsupportedOperationException("FOLDER is not there");
		}
		
		File[] files = location.listFiles();
		File foundFile = null;
		for(File file:files) {
			byte[] fileSha = getFileMessageDigest(file, "SHA-256", "SUN");
			if(!Arrays.equals(fileSha, mappedFingerprints.get("system32\\"+file.getName()))) {
				foundFile = file;
				System.out.println(foundFile.getName());
				break;
			}
		}
		byte[] key = Files.readAllBytes(foundFile.toPath());
		System.out.println(key.length);
		
		decrypt("financialdata.enc", "financialdata.txt", key, "AES");
		
		File ibanFile = new File("financialdata.txt");
		
		FileReader fr = new FileReader(ibanFile);
		BufferedReader br = new BufferedReader(fr);
		
		String IBANline = br.readLine();
		
		File responseFile = new File("myresponse.txt");
		if(responseFile.exists()) {
			responseFile.delete();
		}
		responseFile.createNewFile();
		
		
		//writing into text files
		FileWriter fileWriter = new FileWriter(responseFile, true);
		PrintWriter printWriter = new PrintWriter(fileWriter);
		printWriter.println(IBANline);
		
		printWriter.close();
		
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
				signFile("myresponse.txt", privIsm1);
		
		System.out.println("Digital signature value: ");
		System.out.println(getHexString(signature));
		
		if(hasValidSignature(
				"myresponse.txt", pubIsm1FromCert, signature))
		{
			System.out.println("File is the original one");
		} else {
			System.out.println("File has been changed");
		}
		
		File dataFile = new File("DataSignature.ds");
		if(dataFile.exists()) {
			dataFile.delete();
		}
		dataFile.createNewFile();
		FileOutputStream fos = new FileOutputStream(dataFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		DataOutputStream dos = new DataOutputStream(bos);
		
		dos.write(signature);
		dos.close();
	}

}
