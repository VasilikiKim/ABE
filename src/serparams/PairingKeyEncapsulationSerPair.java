package serparams;
import org.bouncycastle.crypto.CipherParameters;

public class PairingKeyEncapsulationSerPair implements CipherParameters {
    private byte[] sessionKey;//会话密钥，用于解密明文
    private PairingCipherSerParameter header;//除明文加密外的密文

    /**
     * basic constructor.
     *
     * @param sessionKey a byte array session key.
     * @param ciphertextParam the corresponding ciphertext parameters.
     */
    public PairingKeyEncapsulationSerPair(byte[] sessionKey, PairingCipherSerParameter ciphertextParam) {
        this.sessionKey = sessionKey;
        this.header = ciphertextParam;
    }

    /**
     * @return the session key parameters
     */
    public byte[] getSessionKey() { return this.sessionKey; }

    /**
     * @return the header parameters.
     */
    public PairingCipherSerParameter getHeader()
    {
        return this.header;
    }
}