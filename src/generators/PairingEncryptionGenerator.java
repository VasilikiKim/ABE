package generators;

import serparams.PairingCipherSerParameter;
import org.bouncycastle.crypto.CipherParameters;

import algorithm.Lagrange;

/**
 * 基于配对的加密生成器应符合的接口
 */
public interface PairingEncryptionGenerator {

    /**
     * 初始化
     * @param params the parameters the public key pair is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * 生成密文
     * @return a PairingCipherSerParameter representing the ciphertext.
     */
    PairingCipherSerParameter generateCiphertext();
    
}
