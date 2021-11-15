package gpswabe;

import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import genparams.KPABEEngine;
import genparams.KPABEDecryptionGenerationParameter;
import genparams.KPABEEncryptionGenerationParameter;
import genparams.KPABEKeyPairGenerationParameter;
import genparams.KPABESecretKeyGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;


public class GPSWEngine extends KPABEEngine {
    private static final String SCHEME_NAME = "Goyal-Pandey-Sahai-Waters-06 small-universe KP-ABE";

    private static GPSWEngine engine;

    public static GPSWEngine getInstance() {
        if (engine == null) {
            engine = new GPSWEngine();
        }
        return engine;
    }

    GPSWEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        GPSWKeyPairGenerator keyPairGenerator = new GPSWKeyPairGenerator();
        keyPairGenerator.init(new KPABEKeyPairGenerationParameter(pairingParameters, maxAttributesNum));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof GPSWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, GPSWPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof GPSWMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey,GPSWMasterSecretKeySerParameter.class.getName());
        }
        GPSWSecretKeyGenerator secretKeyGenerator = new GPSWSecretKeyGenerator();
        secretKeyGenerator.init(new KPABESecretKeyGenerationParameter(
                accessControlEngine, publicKey, masterKey, accessPolicyIntArrays, rhos));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message) {
        if (!(publicKey instanceof GPSWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, GPSWPublicKeySerParameter.class.getName());
        }
        GPSWEncryptionGenerator encryptionGenerator = new GPSWEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes) {
        if (!(publicKey instanceof GPSWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, GPSWPublicKeySerParameter.class.getName());
        }
        GPSWEncryptionGenerator encryptionGenerator = new GPSWEncryptionGenerator();
        encryptionGenerator.init(new KPABEEncryptionGenerationParameter(publicKey, attributes, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] attributes, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof GPSWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, GPSWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof GPSWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, GPSWSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof GPSWCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, GPSWCiphertextSerParameter.class.getName());
        }
        GPSWDecryptionGenerator decryptionGenerator = new GPSWDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] attributes, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof GPSWPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, GPSWPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof GPSWSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, GPSWSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof GPSWHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, GPSWHeaderSerParameter.class.getName());
        }
       GPSWDecryptionGenerator decryptionGenerator = new GPSWDecryptionGenerator();
        decryptionGenerator.init(new KPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, attributes, header));
        return decryptionGenerator.recoverKey();
    }
}
