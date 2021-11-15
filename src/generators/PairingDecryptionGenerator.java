package generators;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * 解密生成器接口
 * interface that a pairing-based decryption generator should conform to.
 */
public interface PairingDecryptionGenerator {
    /**
     * 初始化解密生成器
     * @param params the parameters the decryption is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * 从密文恢复消息
     * @return the message recovered from the ciphertext.
     */
    Element recoverMessage() throws InvalidCipherTextException;
}
