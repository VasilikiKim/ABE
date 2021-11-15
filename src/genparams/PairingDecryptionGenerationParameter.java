package genparams;

import serparams.PairingCipherSerParameter;
import serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * 解密生成器
 * Pairing decryption generation parameter
 */
public abstract class PairingDecryptionGenerationParameter implements CipherParameters {
    private PairingKeySerParameter publicKeyParameter;
    private PairingKeySerParameter secretKeyParameter;
    private PairingCipherSerParameter ciphertextParameter;

    /**
     * 构造函数，使用公钥、私钥和密文
     * @param publicKeyParameter
     * @param secretKeyParameter
     * @param ciphertextParameter
     */
    public PairingDecryptionGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            PairingCipherSerParameter ciphertextParameter) {
        this.publicKeyParameter = publicKeyParameter;
        this.secretKeyParameter = secretKeyParameter;
        this.ciphertextParameter = ciphertextParameter;
    }
    //获得公钥
    public PairingKeySerParameter getPublicKeyParameter() { return this.publicKeyParameter; }

    //获得私钥
    public PairingKeySerParameter getSecretKeyParameter() { return this.secretKeyParameter; }
    //获得密文
    public PairingCipherSerParameter getCiphertextParameter() { return this.ciphertextParameter; }
}