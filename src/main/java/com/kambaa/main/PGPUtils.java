package com.kambaa.main;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class PGPUtils {

	private static final int KEY_FLAGS = 27;
	private static final int[] MASTER_KEY_CERTIFICATION_TYPES = new int[] { 
			PGPSignature.POSITIVE_CERTIFICATION,
			PGPSignature.CASUAL_CERTIFICATION, 
			PGPSignature.NO_CERTIFICATION, 
			PGPSignature.DEFAULT_CERTIFICATION 
			};
	
	
	public PGPUtils() {
		Security.addProvider(new BouncyCastleProvider());
	}
	

	public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {

		PGPPublicKeyRingCollection keyRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in),new BcKeyFingerprintCalculator());
		PGPPublicKey publicKey = null;
		Iterator<PGPPublicKeyRing> rIt = keyRingCollection.getKeyRings();

		while (publicKey == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
			while (publicKey == null && kIt.hasNext()) {
				PGPPublicKey key = kIt.next();

				if (key.isEncryptionKey()) {
					publicKey = key;
				}
			}
		}

		if (publicKey == null) {
			throw new IllegalArgumentException("Can't find public key in the key ring.");
		}
		
		if (!isForEncryption(publicKey)) {
			throw new IllegalArgumentException("KeyID " + publicKey.getKeyID() + " not flagged for encryption.");
		}
		return publicKey;
	}

	public static void encryptStream(OutputStream out, PGPPublicKey encKey, InputStream streamData) throws IOException, PGPException {
		
		Security.addProvider(new BouncyCastleProvider());

		ArmoredOutputStream aout = new ArmoredOutputStream(out);
		aout.setHeader(ArmoredOutputStream.VERSION_HDR, null);
		aout.setHeader("Copy rights ", " Kambaa Inc");

		out = aout;

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		writeStreamToLiteralData(comData.open(bOut), PGPLiteralDataGenerator.BINARY, PGPLiteralData.CONSOLE,streamData);

		comData.close();

		BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.TRIPLE_DES);
		dataEncryptor.setWithIntegrityPacket(true);
		dataEncryptor.setSecureRandom(new SecureRandom());

		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
		encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encKey));

		byte[] bytes = bOut.toByteArray();
		OutputStream cOut = encryptedDataGenerator.open(out, bytes.length);
		cOut.write(bytes);
		cOut.close();
		out.close();
	}

	@SuppressWarnings("unchecked")
	public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpF = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
		PGPEncryptedDataList enc;

		Object o = pgpF.nextObject();

		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}


		Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;

		while (sKey == null && it.hasNext()) {
			pbe = it.next();

			sKey = findPrivateKey(keyIn, pbe.getKeyID(), passwd);
		}

		if (sKey == null) {
			throw new IllegalArgumentException("Secret key for message not found.");
		}

		InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));

		PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

		Object message = plainFact.nextObject();

		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());

			message = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;

			InputStream unc = ld.getInputStream();
			int ch;

			while ((ch = unc.read()) >= 0) {
				out.write(ch);
			}
		} else if (message instanceof PGPOnePassSignatureList) {
			throw new PGPException("Encrypted message contains a signed message - not literal data.");
		} else {
			throw new PGPException("Message is not a simple encrypted file - type unknown.");
		}

		if (pbe.isIntegrityProtected()) {
			if (!pbe.verify()) {
				throw new PGPException("Message failed integrity check");
			}
		}
	}


	public static PGPPrivateKey findPrivateKey(InputStream keyIn, long keyID, char[] pass)
			throws IOException, PGPException, NoSuchProviderException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn),
				new BcKeyFingerprintCalculator());
		return findPrivateKey(pgpSec.getSecretKey(keyID), pass);

	}


	public static PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecKey, char[] pass) throws PGPException {
		if (pgpSecKey == null)
			return null;

		PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
				.build(pass);
		return pgpSecKey.extractPrivateKey(decryptor);
	}

	

	private static void writeStreamToLiteralData(OutputStream os, char fileType, String name, InputStream streamData)
			throws IOException {
		int bufferLength = 2048;

		byte[] buff = new byte[bufferLength];
		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		OutputStream pOut = lData.open(os, fileType, name, PGPLiteralData.NOW, buff);

		byte[] buffer = new byte[bufferLength];
		int len;
		while ((len = streamData.read(buffer)) > 0) {
			pOut.write(buffer, 0, len);
		}

		pOut.close();
	}

	@SuppressWarnings("deprecation")
	public static boolean isForEncryption(PGPPublicKey key) {
		if (key.getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN || key.getAlgorithm() == PublicKeyAlgorithmTags.DSA
				|| key.getAlgorithm() == PublicKeyAlgorithmTags.EC
				|| key.getAlgorithm() == PublicKeyAlgorithmTags.ECDSA) {
			return false;
		}

		return hasKeyFlags(key, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
	}

	@SuppressWarnings("unchecked")
	private static boolean hasKeyFlags(PGPPublicKey encKey, int keyUsage) {
		if (encKey.isMasterKey()) {
			for (int i = 0; i != PGPUtils.MASTER_KEY_CERTIFICATION_TYPES.length; i++) {
				for (Iterator<PGPSignature> eIt = encKey
						.getSignaturesOfType(PGPUtils.MASTER_KEY_CERTIFICATION_TYPES[i]); eIt.hasNext();) {
					PGPSignature sig = eIt.next();
					if (!isMatchingUsage(sig, keyUsage)) {
						return false;
					}
				}
			}
		} else {
			for (Iterator<PGPSignature> eIt = encKey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING); eIt.hasNext();) {
				PGPSignature sig = eIt.next();
				if (!isMatchingUsage(sig, keyUsage)) {
					return false;
				}
			}
		}
		return true;
	}

	private static boolean isMatchingUsage(PGPSignature sig, int keyUsage) {
		if (sig.hasSubpackets()) {
			PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
			if (sv.hasSubpacket(PGPUtils.KEY_FLAGS)) {
				if (sv.getKeyFlags() == 0 && keyUsage == 0) {
					return false;
				}
			}
		}
		return true;
	}

}
