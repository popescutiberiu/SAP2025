package ism.ase.ro;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		for(byte b : value) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}
	
	public static byte[] getHmac(String input, String secret, String algorithm) 
			throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac hmac = Mac.getInstance(algorithm);
		Key hmacKey = new SecretKeySpec(secret.getBytes(), algorithm);
		hmac.init(hmacKey);
		
		return hmac.doFinal(input.getBytes());
	}
	
	public static byte[] getHash(String input, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
		MessageDigest md = MessageDigest.getInstance(algorithm, "SUN");
		return md.digest(input.getBytes());
	}
	
	static String computeSum(File file) throws IOException {
		FileReader fr = new FileReader(file);
		BufferedReader br = new BufferedReader(fr);
		String line = br.readLine();
		br.close();
		
		int indexPl = line.indexOf("+");
		int indexEq = line.indexOf("=");
		
		String part1 = line.substring(0,indexPl).trim();
		String part2 = line.substring(indexPl+1, indexEq).trim();
		
		//System.out.println(part1);
		//System.out.println(part2);

		int number1 = Integer.parseInt(part1);
		int number2 = Integer.parseInt(part2);
		int sum = number1+number2;
		
		return sum+"";
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
		
		Cipher cipher = Cipher.getInstance(algorithm + "/CTR/NoPadding");
		
		//getting the IV from the file
		byte[] IV = new byte[cipher.getBlockSize()];
		IV[15] = (byte)0x33;
		
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
	
	public static void encrypt(
			String filename, String cipherFilename, byte[] password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
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
		
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		SecretKeySpec key = new SecretKeySpec(password, algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		
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
		//get the last ciphertext block
		byte[] lastBlock = cipher.doFinal();
		fos.write(lastBlock);
		
		fis.close();
		fos.close();
	}
	
	
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
		String hmac = "c1779745da19a6de1795cfcc5cd10f8a8d4ec93be1e27013ffb668a2dcbf7a3d";
		File location = new File("Messages");
		if(!location.exists()) {
			throw new FileNotFoundException("Messages Folder Missing");
		}
		
		File foundFile = null;
		File[] files = location.listFiles();
		
		for(File file:files) {
			FileReader fr = new FileReader(file);
			BufferedReader br = new BufferedReader(fr);
			String line = br.readLine();
			br.close();
			String fileHmac = getHexString(getHmac(line, "ismsecret","HmacSHA256"));
			//System.out.println(fileHmac);
			if(fileHmac.equals(hmac)) {
				foundFile = file;
				System.out.println(foundFile.getName());
				break;
			}
		}
		String sum = computeSum(foundFile);
		System.out.println(sum);
		byte[] hashedKey = getHash(sum, "MD5");
		String questionFile = "Questions\\"+foundFile.getName();
		questionFile = questionFile.replace("Message", "Question");
		questionFile = questionFile.replace("txt", "enc");
		System.out.println(questionFile);
		decrypt(questionFile, "Question.txt", hashedKey, "AES");
		
		File nameFile = new File("response.txt");
		if(!nameFile.exists()) {
			nameFile.createNewFile();
		}
		
		FileWriter frName = new FileWriter(nameFile);
		PrintWriter brName = new PrintWriter(frName);
		brName.println("Popescu Tiberiu");
		brName.close();
		
		encrypt("response.txt", "response.enc", hashedKey, "AES");
		
		
	}

}
