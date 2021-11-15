package genparams;

import acess.AccessControlEngine;
import acess.ParserUtils;
import acess.PolicySyntaxException;
import acess.AccessTreeEngine;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;


public abstract class KPABEEngine extends Engine {
    protected AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    protected KPABEEngine(String schemeName, ProveSecModel proveSecModel, PayloadSecLevel payloadSecLevel, PredicateSecLevel predicateSecLevel) {
        super(schemeName, proveSecModel, payloadSecLevel, predicateSecLevel);
    }

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.accessControlEngine.isSupportThresholdGate();
    }

    /**
     * Setup Algorithm for KP-ABE
     * @param pairingParameters Pairing Parameters
     * @param maxAttributesNum maximal number of attributes supported, useless if no such limitation
     * @return public key / master secret key pair of the scheme
     */
    public abstract PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum);

    /**
     * Secret Key Generation Algorithm for KP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param accessPolicy associated access policy, given by strings
     * @return secret key associated with the access policy
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     */
    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return keyGen(publicKey, masterKey, accessPolicyIntArrays, rhos);
    }

    /**
     * Secret Key Generation Algorithm for KP-ABE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos associated rhos, given by string array
     * @return secret key associated with the access policy
     */
    public abstract PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int[][] accessPolicyIntArrays, String[] rhos);

    /**
     * Encryption algorithm for KP-ABE
     * @param publicKey public key
     * @param attributes associated attribute set
     * @param message message in GT
     * @return ciphertext associated with the attribute set
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] attributes, Element message);

    /**
     * Encapsulation algorithm for KP-ABE
     * @param publicKey public key
     * @param attributes associated attribute set
     * @return header / session key pair
     */
    public abstract PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] attributes);

    /**
     * Decryption Algorithm for KP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an access policy
     * @param attributes attribute set associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the message in GT
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public abstract Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                       String[] attributes, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException;

    /**
     * Decapsulation Algorithm for KP-ABE
     * @param publicKey public key
     * @param secretKey secret key associated with an access policy
     * @param attributes attribute set associating with the ciphertext
     * @param header header
     * @return session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    public abstract byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                       String[] attributes, PairingCipherSerParameter header) throws InvalidCipherTextException;
}