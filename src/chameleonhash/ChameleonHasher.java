package chameleonhash;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;

/**
 * Chameleon哈希方案接口
 */
public interface ChameleonHasher {
    /**
     *初始化哈希，用于寻找碰撞或计算哈希值
     * @param forCollisionFind true if for finding a hash collision, false otherwise
     * @param param necessary parameters.
     */
    void init(boolean forCollisionFind, CipherParameters param);

    /**
     * 使用字节b更新内部摘要
     */
    void update(byte b);

    /**
     *  使用数组in更新内部摘要
     */
    void update(byte[] in, int off, int len);

    /**
     * 使用经过初始化的密钥计算加载的消息的哈希值
     */
    byte[][] computeHash() throws CryptoException, DataLengthException;

    /**
     * 使用经过初始化的密钥计算加载的消息的哈希值和之前使用的chameleon哈希值(用了随机值r)
     */
    byte[][] computeHash(byte[] cHashResult, byte[] auxiliaryParameters) throws CryptoException, DataLengthException;

    byte[][] findCollision(byte[] cHashResult, byte[] auxiliaryParameters);

    /**
     * 重置内部状态
     */
    void reset();
}