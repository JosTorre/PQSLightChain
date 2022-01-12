 package signature;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;

/* OQS Libraries */
import java.org.openquantumsafe.*;
import java.util.ArrayList;
import java.util.Arrays;

public class DigitalSignature {
	
	/* private static String genAlgorithm = "RSA";
	private static String signAlgorithm = "SHA256withRSA"; */

	private static String sig_name = "Falcon-1024";
    private static Signature signer = new Signature(sig_name);
	private static Signature verifier = new Signature(sig_name);

	/* private PrivateKey privateKey;
	private PublicKey publicKey; */

	/* private String privateKeyName;
	private String publicKeyName; */

	private String keysPath;
	private static Scanner in = new Scanner(System.in);
	private ArrayList<String> otherPubKeys;
	
	
	/*
	 * A constructor for the digital signature
	 * Once we declare a digital signature for a node
	 * we generate a public-private key pair for the node given a certain algorithm
	 */
	public DigitalSignature() {
		try {
			
			byte[] signer_keys = signer.generate_keypair();

			privateKey = signer_keys.export_public_key();
			publicKey = signer_keys.export_secret_key();
			otherPubKeys = new ArrayList<>();
			privateKeyName = "privateKey";
			publicKeyName = "publicKey";
			keysPath = "";
			storeKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * A method that stores the public and private key on disk.
	 */
	private void storeKeyPair() {
		
		try {
			//Initialize folder
			File parentDir = new File(System.getProperty("user.dir")+File.separator+"Keys");
			parentDir.mkdirs();
			FileOutputStream out = new FileOutputStream(System.getProperty("user.dir")+File.separator+"Keys"+File.separator+privateKeyName + ".key");
			out.write(privateKey.getEncoded()); /* Not sure if this is correct, maybe without encoding*/
			out.close();
			out = new FileOutputStream(System.getProperty("user.dir")+File.separator+"Keys"+File.separator+publicKeyName + ".key");
			out.write(publicKey.getEncoded()); /* Not sure if this is correct, maybe without encoding*/
			out.close();
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 * A method that loads public and private key from disk 
	 */
	public KeyPair loadKeyPair(String path, String algorithm) {
		
		try {
			Path p = Paths.get(keysPath + "\\" + publicKeyName + ".key");
			byte[] pb;
			pb = Files.readAllBytes(p);
			/* X509EncodedKeySpec pub = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			PublicKey pb = kf.generatePublic(pub); */

			
			p = Paths.get(keysPath + "\\" + privateKeyName + ".key");
			byte[] pr;
			pr = Files.readAllBytes(p);
			/* PKCS8EncodedKeySpec pri = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kk = KeyFactory.getInstance(algorithm);
			PrivateKey pr = kk.generatePrivate(pri); */
			return new KeyPair(pb,pr);
				
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/*
	 * A method to store a given public key on disk
	 */
	public void storeKey(String path, String name, PublicKey key) {
		otherPubKeys.add(path + "\\" + name + ".key");
		try {
			FileOutputStream out = new FileOutputStream(path + "\\" + name + ".key");
			out.write(key.getEncoded()); /* Not sure if this is correct, maybe without encoding*/
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/*
	 * A method to load a public key that is stored on disk
	 */
	public PublicKey loadKey(String path, String name, String algorithm) {
		Path p = Paths.get(path + "\\" + name + ".key");
		byte[] bytes;
		try {
			bytes = Files.readAllBytes(p);
			/* X509EncodedKeySpec pub = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance(algorithm);
			PublicKey pb = kf.generatePublic(pub); */
			return bytes;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/*
	 * This method takes a string, signs it, and then returns the signed string
	 */
	public SignedBytes signString(String text) {
		
		/* Signature signature; */
		try {	
			/* signature = Signature.getInstance(signAlgorithm);
			signature.initSign(privateKey); */

			byte[] data = text.getBytes("UTF-8");

			/* signature.update(data);
			byte[] signed = signature.sign();
			return new SignedBytes(signed); */

			byte[] signature = signer.sign(data);
			return new SignedBytes(signature);
			
		} catch (Exception e) {
			log("Exception caught: " + e.toString());
			e.printStackTrace();
			return null;
		}
	}

	/*
	 * This method takes a path of a file, signs it, and then generates the signed file
	 * in the same path of the of the given file
	 * and returns true if the signing operation was successful and false otherwise
	 */
	public boolean signFile(String filePath) {
		
		/* Signature signature; */
		try {
			/* signature = Signature.getInstance(signAlgorithm);
			signature.initSign(privateKey); */
			
			Path path = FileSystems.getDefault().getPath(filePath);
			byte[] data = Files.readAllBytes(path);

			/*
			signature.update(data);
			byte[] signed = signature.sign(); */

			byte[] signature = signer.sign(data);
			
			FileOutputStream signedFile = new FileOutputStream(filePath+"_Signature");
			signedFile.write(signature);
			signedFile.close();
			return true;
			
		}catch(Exception e) {
			log("Exception caught: " + e.toString());
			e.printStackTrace();
			return false;
		} 
	}
	
	/* 
	 * This methods receives a string and the signed data and verifies it
	 * It returns true if the operation is successful and false otherwise
	 */
	public boolean verifyString(String data, SignedBytes signedData, PublicKey pKey) {
			
		/* Signature signature ; */
		Signature verifier = new Signature(sig_name);

		try {
			/* signature = Signature.getInstance(signAlgorithm);
			signature.initVerify(pKey);
			signature.update(data.getBytes()); */
			if(signedData==null || signedData.getBytes()==null) return false;
			boolean verification = verifier.verify(data.getBytes(), signedData.getBytes(), pKey);
			return verification;
		}catch(Exception e) {
			log("Exception caught: " + e.toString());
			e.printStackTrace();
			return false;
		}
	}
	
	/*
	 * This method receives that paths of a data file and a signed file and verifies the data file
	 * It return true if the operation is successful and false otherise.
	 */
	public boolean verifyFile(String filePath, String signedPath, PublicKey pKey) {
		
		Signature verifier = new Signature(sig_name);

		try {
			FileInputStream input = new FileInputStream(signedPath);
			byte[] data = new byte[input.available()];
			input.read(data);
			input.close();
			signature = Signature.getInstance(signAlgorithm);
			signature.initVerify(pKey);
			FileInputStream dataFile = new FileInputStream(filePath);
			BufferedInputStream dataBuffered = new BufferedInputStream(dataFile);
			byte[] buffer = new byte[1024];
			int len ;
			while(dataBuffered.available() != 0) {
				len = dataBuffered.read(buffer);
				signature.update(buffer,0,len);
			}
			dataBuffered.close();
			boolean verification = verifier.verify(data, signedPath, pKey);
			return verification;
		}catch(Exception e) {
			log("Exception caught: " + e.toString());
			e.printStackTrace();
			return false;
		}
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public static void log(String s) {
		System.out.println(s);
	}
	public static String get() {
		String res = in.nextLine();
		return res;
	}
}
