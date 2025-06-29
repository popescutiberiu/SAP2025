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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	private static final String HASH_ALGORITHM = "MD5";
    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final String SHARED_SECRET = "ZsEE\";t1hFh91234"; // Secret key for HMAC authentication from the Excel file
    private static final String AES_ALGORITHM = "";
    private static final String FOLDER_PATH = "messages";


    static byte[] getHash(String filename) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
    	File file = new File(filename);
		if(!file.exists())
			System.out.println("************* The file is not there");
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM, "SUN");
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
    
    public static String getHexString(byte[] value) {
		StringBuilder result = new StringBuilder();
		for(byte b : value) {
			result.append(String.format("%02X", b));
		}
		return result.toString();
	}
    
    // Step 1: Generate Digest values of all the files from the given folder
    public static void generateFilesDigest(String folderPath) throws Exception {
    	File location = new File(folderPath);
    	if(!location.exists()) {
    		throw new FileNotFoundException("Messages folder not found");
    	}
    	
    	File[] files = location.listFiles();
    	
    	for(File file:files) {
    		byte[] hashedFile = getHash("messages\\"+file.getName());
    		String hash = getHexString(hashedFile);
    		File hashFile = new File("hashes\\"+file.getName().replace("txt", "digest"));
    		if(hashFile.exists()) {
    			hashFile.delete();
    		}
    		hashFile.createNewFile();
    		FileWriter fr = new FileWriter(hashFile);
    		PrintWriter pr = new PrintWriter(fr);
    		pr.println(hash);
    		pr.close();
    	}
    	
    	
    }

    
    public static byte[] getFileHmac(
			String filename)
					throws NoSuchAlgorithmException, InvalidKeyException, IOException {
		
		File file = new File(filename);
		if(!file.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		
		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);
		
		Mac hmac = Mac.getInstance(HMAC_ALGORITHM);
		Key hmacKey = new SecretKeySpec(SHARED_SECRET.getBytes(), HMAC_ALGORITHM);
		hmac.init(hmacKey);
		
		byte[] buffer = new byte[16];
		int noBytes = 0;
		
		while(true) {
			noBytes = bis.read(buffer);
			if(noBytes == -1) {
				break;
			}
			hmac.update(buffer, 0, noBytes);
		}
		
		bis.close();
		
		return hmac.doFinal();
		
	}
    // Step 2: Generate HMAC-SHA256 authentication code
    public static void generateFilesHMAC(String folderPath, String secretKey) throws Exception {
    	File location = new File(folderPath);
    	if(!location.exists()) {
    		throw new FileNotFoundException("Messages folder not found");
    	}
    	
    	File[] files = location.listFiles();
    	
    	for(File file:files) {
    		byte[] hmacedFile = getFileHmac("messages\\"+file.getName());
    		String hmac = Base64.getEncoder().encodeToString(hmacedFile);
    		File hmacFile = new File("hmacs\\"+file.getName().replace("txt", "hmac"));
    		if(hmacFile.exists()) {
    			hmacFile.delete();
    		}
    		hmacFile.createNewFile();
    		FileWriter fr = new FileWriter(hmacFile);
    		PrintWriter pr = new PrintWriter(fr);
    		pr.println(hmac);
    		pr.close();
    	}
    	
    }
    

    // Step 3: Decrypt and verify the document
    public static boolean retrieveAndVerifyDocument(String file, String hashFile, String hmacFile, String secretKey) throws Exception {
        
    	String hmacName = "hmacs\\"+hmacFile;
    	String hashName = "hashes\\"+hashFile;
    	
    	File fileWithHmac = new File(hmacName);
    	File fileWithHash = new File(hashName);

    	
    	FileReader frHmac = new FileReader(fileWithHmac);
    	BufferedReader brHmac = new BufferedReader(frHmac);
    	String encodedHmac = brHmac.readLine().trim();
    	brHmac.close();
    	
    	FileReader frHash = new FileReader(fileWithHash);
    	BufferedReader brHash = new BufferedReader(frHash);
    	String hexHash = brHash.readLine().trim();
    	brHash.close();
    	
    	byte[] rawHmac = getFileHmac("messages\\"+file);
    	byte[] rawHash = getHash("messages\\"+file);
    	
    	if(hexHash.equals(getHexString(rawHash))&& encodedHmac.equals(Base64.getEncoder().encodeToString(rawHmac))) {
    		return true;
    	}

    	
    	
    	return false;
    }
    
    // Step 4: Generate AES key from the shared secret. See Excel for details
    public static byte[] generateSecretKey(String sharedSecret) throws Exception {
    	
    	byte[] key = sharedSecret.getBytes();
    	key[13] ^= (byte)(1 << (8-5));
    	key = Arrays.copyOf(key, 16);
    	return key;
    }


    // Step 5: Encrypt document with AES and received key
    public static void encryptDocument(String filePath, byte[] key) throws Exception {
    	File inputFile = new File("messages\\"+filePath);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(filePath.replace("txt", "enc"));
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance( "AES/ECB/PKCS5Padding");
		SecretKeySpec secretkey = new SecretKeySpec(key, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretkey);
		
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

    public static void decrypt(
			String filename, String outputFilename, byte[] password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		File inputFile = new File(filename);
		if(!inputFile.exists()) {
			throw new UnsupportedOperationException("Missing file");
		}
		File cipherFile = new File(outputFilename);
		if(!cipherFile.exists()) {
			cipherFile.createNewFile();
		}
		
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(cipherFile);
		
		Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
		SecretKeySpec key = new SecretKeySpec(password, algorithm);
		
		cipher.init(Cipher.DECRYPT_MODE, key);
		
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
    
    
    public static void main(String[] args) {


        try {
            // Step 1: Generate and store file digest
            generateFilesDigest(FOLDER_PATH);

            // Step 2: Generate and store HMAC for file authentication
            generateFilesHMAC(FOLDER_PATH, SHARED_SECRET);
            
            String filename = "message_3_hid177.txt"; //choose any message.txt file from the folder and test it
            String hashFile = "message_3_hid177.digest"; //the corresponding hash file
            String hmacFile = "message_3_hid177.hmac"; //the corresponding hmac file
            
            // Step 3: Verify the document
            if (retrieveAndVerifyDocument(filename, hashFile, hmacFile, SHARED_SECRET)) {
                System.out.println("Document retrieved successfully. Integrity verified.");
            } else {
                System.out.println("Document verification failed!");
            }
            
            //Step 3: Change the file content and re-check it to be sure your solution is correct
            
            
            // Step 4: Get the derived key
            byte[] derivedKey = generateSecretKey(SHARED_SECRET);

            // Step 5: Encrypt the document
            encryptDocument(filename, derivedKey);
            decrypt("message_3_hid177.enc", "restored.txt", derivedKey, "AES");


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
