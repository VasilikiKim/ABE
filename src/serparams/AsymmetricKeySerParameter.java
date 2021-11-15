package serparams;

import org.bouncycastle.crypto.CipherParameters;

//非对称密钥参数（私钥）
public class AsymmetricKeySerParameter implements CipherParameters, java.io.Serializable {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private boolean privateKey;//是否为私钥

	/**
	 * 构造函数
	 * @param privateKey
	 */
    public AsymmetricKeySerParameter(boolean privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * 判断是否是私钥
     * @return
     */
    public boolean isPrivate()
    {
        return privateKey;
    }

    /**
     * 判断两实例是否相等
     */
    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof AsymmetricKeySerParameter) {
            AsymmetricKeySerParameter that = (AsymmetricKeySerParameter)anOjbect;
            //Compare Pairing Parameters
            return (this.privateKey == that.privateKey);
        }
        return false;
    }
}
