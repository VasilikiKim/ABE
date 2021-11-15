package swabe;

import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import genparams.CPABEEngine2;
import genparams.CPABEDecryptionGenerationParameter;
import genparams.CPABEEncryptionGenerationParameter;
import genparams.CPABEKeyPairGenerationParameter;
import genparams.CPABESecretKeyGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;


public class SWEngine extends CPABEEngine2 {
    private static final String SCHEME_NAME = "Bethencourt-Sahai-Waters large-universe CP-ABE";

    private static SWEngine engine;

    public static SWEngine getInstance() {
        if (engine == null) {
            engine = new SWEngine();
        }
        return engine;
    }

    SWEngine() {
        super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        SWKeyPairGenerator keyPairGenerator = new SWKeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof SWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, SWPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof SWMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, SWMasterSecretKeySerParameter.class.getName());
        }
        SWSecretKeyGenerator secretKeyGenerator = new SWSecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof SWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, SWPublicKeySerParameter.class.getName());
        }
        SWEncryptionGenerator encryptionGenerator = new SWEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof SWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, SWPublicKeySerParameter.class.getName());
        }
        SWEncryptionGenerator encryptionGenerator = new SWEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof SWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey,SWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof SWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SWSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof SWCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, SWCiphertextSerParameter.class.getName());
        }
        SWDecryptionGenerator decryptionGenerator = new SWDecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof SWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, SWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof SWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, SWSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof SWHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, SWHeaderSerParameter.class.getName());
        }
        SWDecryptionGenerator decryptionGenerator = new SWDecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}