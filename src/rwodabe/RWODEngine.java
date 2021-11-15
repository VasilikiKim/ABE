package rwodabe;

import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import genparams.CPABEEngine2;
import genparams.CPABEDecryptionGenerationParameter;
import genparams.CPABEEncryptionGenerationParameter;
import genparams.CPABEKeyPairGenerationParameter;
import genparams.CPABESecretKeyGenerationParameter;
import genparams.Engine.PayloadSecLevel;
import genparams.Engine.PredicateSecLevel;
import genparams.Engine.ProveSecModel;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class RWODEngine extends CPABEEngine2  {

	private static final String SCHEME_NAME = "Rousekalis-Waters-13 large-universe CP-ABE With Outsourcing Decryption ";
    private static RWODEngine engine;

    public static RWODEngine getInstance() {
        if (engine == null) {
            engine = new RWODEngine();
        }
        return engine;
    }
	
    RWODEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }
	
    //SetUp
    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        RWODKeyPairGenerator keyPairGenerator = new RWODKeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }
    
    //KeyGen-out
    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof RWODPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWODPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RWODMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, RWODMasterSecretKeySerParameter.class.getName());
        }
        RWODSecretKeyGenerator secretKeyGenerator = new RWODSecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
        return secretKeyGenerator.generateKeyOut();
    }
    
    //Encrypt
    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof RWODPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWODPublicKeySerParameter.class.getName());
        }
        RWODEncryptionGenerator encryptionGenerator = new RWODEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));
        return encryptionGenerator.generateCiphertext();
    }
    
    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof RWODPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWODPublicKeySerParameter.class.getName());
        }
        RWODEncryptionGenerator encryptionGenerator = new RWODEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));
        return encryptionGenerator.generateEncryptionPair();
    }
    
public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
            int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
throws InvalidCipherTextException {
if (!(publicKey instanceof RWODPublicKeySerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWODPublicKeySerParameter.class.getName());
}
if (!(secretKey instanceof RWODSecretKeySerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RWODSecretKeySerParameter.class.getName());
}
if (!(ciphertext instanceof RWODCiphertextSerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, RWODCiphertextSerParameter.class.getName());
}
RWODDecryptionGenerator decryptionGenerator = new RWODDecryptionGenerator();
decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));

    return decryptionGenerator.recoverMessage();
}
    
    
    
public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
            int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
throws InvalidCipherTextException {
if (!(publicKey instanceof RWODPublicKeySerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWODPublicKeySerParameter.class.getName());
}
if (!(secretKey instanceof RWODSecretKeySerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RWODSecretKeySerParameter.class.getName());
}
if (!(header instanceof RWODHeaderSerParameter)){
PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, RWODHeaderSerParameter.class.getName());
}
RWODDecryptionGenerator decryptionGenerator = new RWODDecryptionGenerator();
decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
return decryptionGenerator.recoverKey();
}


	
}
