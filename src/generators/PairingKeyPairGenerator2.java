package generators;

import serparams.PairingKeySerPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * 非对称序列化密钥对生成器
 */
public interface PairingKeyPairGenerator2 {
    /**
     * 初始化生成器
     * @param param the parameters the key pair is to be initialised with.
     */
    void init(KeyGenerationParameters param);

    /**
     * 生成密钥对
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    PairingKeySerPair generateKeyPair();
    //PairingKeySerPair generateKeyPair(String[] rhos);
}