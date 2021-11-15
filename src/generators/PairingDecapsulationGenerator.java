package generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * 密钥封装机制解密生成器接口
 * interface that a pairing KEM decryption generator should conform to.
 */
public interface PairingDecapsulationGenerator {
    /**
     *初始化
     * @param params the parameters the decapsulation is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * 返回从密文中恢复的会话密钥
     * @return the session key recovered from the ciphertext.
     */
    byte[] recoverKey() throws InvalidCipherTextException;
}