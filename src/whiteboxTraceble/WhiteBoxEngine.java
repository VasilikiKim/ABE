package whiteboxTraceble;

import org.bouncycastle.crypto.InvalidCipherTextException;

import genparams.CPABEDecryptionGenerationParameter;
import genparams.CPABEEncryptionGenerationParameter;
import genparams.CPABEEngine;
import genparams.CPABEKeyPairGenerationParameter;
import genparams.CPABESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import utils.PairingUtils;

public class WhiteBoxEngine extends CPABEEngine{

	private static final String SCHEME_NAME = "White Box Traceble CP-ABE";
	
	private static WhiteBoxEngine engine;
	
	public static WhiteBoxEngine getInstance() {
		if (engine == null) {
			engine = new WhiteBoxEngine();
		}
		return engine;
	}
	
	protected WhiteBoxEngine() {
		super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON );
	}
	
	public PairingKeySerPair setup(PairingParameters pairingParameters, int maxNum, String[] attributeUniverse ) {
		KeyPairGenerator keyPair = new KeyPairGenerator();
		keyPair.init(new CPABEKeyPairGenerationParameter(pairingParameters));
		
		return keyPair.generateKeyPair(attributeUniverse);
	}
	
	public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey,PairingKeySerParameter masterKey, String[] attributes) {
		if(!(publicKey instanceof PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
		}
		if(!(masterKey instanceof MasterSecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, MasterSecretKeySerParameter.class.getName());
		}
		SecretKeyGenerator secretKey = new SecretKeyGenerator();
		secretKey.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
		return secretKey.generateKey();
	}
	
	public CiphertextSerParameter encryption (PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
		if(!(publicKey instanceof PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
		}
		EncryptionGenerator encryptionGenerator = new EncryptionGenerator();
		encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
				accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));
		return encryptionGenerator.generateCiphertext();
	}
	
	public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
		if(!(publicKey instanceof PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
		}
		EncryptionGenerator encryptionGenerator = new EncryptionGenerator();
		encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
				accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));
		
		return encryptionGenerator.generateEncryptionPair();
	}
	
	public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
			int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext) 
			throws InvalidCipherTextException{
		if(!(publicKey instanceof PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
		}
		if(!(secretKey instanceof SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SecretKeySerParameter.class.getName());
		}
		if(!(ciphertext instanceof CiphertextSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CiphertextSerParameter.class.getName());
		}
		
		DecryptionGenerator decryptionGenerator = new DecryptionGenerator();
		decryptionGenerator.init(new CPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
		return decryptionGenerator.recoverMessage();
	}
	
	public byte[] decapsulation (PairingKeySerParameter publicKey, PairingKeySerParameter secretKey, int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header) throws InvalidCipherTextException{
		if(!(publicKey instanceof PublicKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
		}
		if(!(secretKey instanceof SecretKeySerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SecretKeySerParameter.class.getName());
		}
		if(!(header instanceof HeaderSerParameter)) {
			PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, HeaderSerParameter.class.getName());
		}
		
		DecryptionGenerator decryption = new DecryptionGenerator();
		decryption.init(new CPABEDecryptionGenerationParameter(accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
		return decryption.recoverKey();
	}
}
