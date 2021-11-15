package generators;

import serparams.AsymmetricKeySerPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * 非对称密钥对生成器接口
 * Asymmetric key pair generator.
 */
public interface AsymmetricKeySerPairGenerator {
    /**
     * 初始化
     * @param param the parameters the key pair is to be initialised with.
     */
    void init(KeyGenerationParameters param);

    /**
     * 返回生成的密钥对
     * @return an AsymmetricCipherKeyPair containing the generated keys.
     */
    AsymmetricKeySerPair generateKeyPair();
}
