package generators;

import serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * 基于配对的序列化密钥参数生成器
 */
public interface PairingKeyParameterGenerator {

    void init(KeyGenerationParameters keyGenerationParameters);

    //PairingKeySerParameter generateKey();
    
}
