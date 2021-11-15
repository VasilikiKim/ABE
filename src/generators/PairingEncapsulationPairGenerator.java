package generators;

import serparams.PairingKeyEncapsulationSerPair;
import org.bouncycastle.crypto.CipherParameters;

/**
 * 密钥封装生成器接口
 * interface that a pairing KEM encryption pair generator should conform to.
 */

public interface PairingEncapsulationPairGenerator {

    /**
     * 初始化
     * @param params the parameters the public key pair is to be initialised with.
     */
    void init(CipherParameters params);

    /**
     * 生成会话密钥和密文
     * @return an PairingKeyEncapsulationSerPair containing the generated session key and the ciphertext.
     */
   PairingKeyEncapsulationSerPair generateEncryptionPair();
   
}
