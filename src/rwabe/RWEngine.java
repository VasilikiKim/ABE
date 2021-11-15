package rwabe;
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

public class RWEngine extends CPABEEngine2 {
	private static final String SCHEME_NAME = "Rousekalis-Waters-13 large-universe CP-ABE";
    private static RWEngine engine;

    public static RWEngine getInstance() {
        if (engine == null) {
            engine = new RWEngine();
        }
        return engine;
    }

    RWEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        RWKeyPairGenerator keyPairGenerator = new RWKeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof RWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RWMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, RWMasterSecretKeySerParameter.class.getName());
        }
        RWSecretKeyGenerator secretKeyGenerator = new RWSecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof RWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWPublicKeySerParameter.class.getName());
        }
        RWEncryptionGenerator encryptionGenerator = new RWEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof RWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWPublicKeySerParameter.class.getName());
        }
        RWEncryptionGenerator encryptionGenerator = new RWEncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));
        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof RWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RWSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RWCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, RWCiphertextSerParameter.class.getName());
        }
        RWDecryptionGenerator decryptionGenerator = new RWDecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof RWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RWSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof RWHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, RWHeaderSerParameter.class.getName());
        }
       RWDecryptionGenerator decryptionGenerator = new RWDecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}
