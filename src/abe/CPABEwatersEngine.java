package abe;

import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import genparams.CPABEEngine;
import genparams.CPABEDecryptionGenerationParameter;
import genparams.CPABEEncryptionGenerationParameter;
import genparams.CPABEKeyPairGenerationParameter;
import genparams.CPABESecretKeyGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;


public class CPABEwatersEngine extends CPABEEngine {
    private static final String SCHEME_NAME = "Waters CP-ABE";

    private static CPABEwatersEngine engine;

    public static CPABEwatersEngine getInstance() {
        if (engine == null) {
            engine = new CPABEwatersEngine();
        }
        return engine;
    }
// private CPABEwatersEngine()
     CPABEwatersEngine() {
        super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }
     
     
     

    //初始化
    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum,String[] attributeUnivese) {
       KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair(attributeUnivese);
    }

    //私钥生成
    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, MasterSecretKeySerParameter.class.getName());
        }
       SecretKeyGenerator secretKeyGenerator = new SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));

        return secretKeyGenerator.generateKey();
    }

    //加密
    public CiphertextSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
        }
       
        EncryptionGenerator encryptionGenerator = new EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
        }
        EncryptionGenerator encryptionGenerator = new EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    //解密
    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext,CiphertextSerParameter.class.getName());
        }
       DecryptionGenerator decryptionGenerator = new DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, HeaderSerParameter.class.getName());
        }
        DecryptionGenerator decryptionGenerator = new DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}