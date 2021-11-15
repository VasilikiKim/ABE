package serparams;

import org.bouncycastle.crypto.CipherParameters;

/*配对中的密钥对*/
public class PairingKeySerPair {
    
	private PairingKeySerParameter publicParam;//公钥部分参数
    private PairingKeySerParameter privateParam;//密钥部分参数

    /**构造函数
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
    */
    public PairingKeySerPair(PairingKeySerParameter publicParam, PairingKeySerParameter privateParam)
        {
            this.publicParam = publicParam;
            this.privateParam = privateParam;
        }

        /**
         * 构造函数（out of date）
         * @param publicParam a public key parameters object.
         * @param privateParam the corresponding private key parameters.
         * @deprecated use AsymmetricKeyParameter
         */
    public PairingKeySerPair(CipherParameters publicParam, CipherParameters privateParam)
        {
            this.publicParam = (PairingKeySerParameter)publicParam;
            this.privateParam = (PairingKeySerParameter)privateParam;
        }

    /**
     * 返回密钥对中的公钥部分
     * @return
     */
    public PairingKeySerParameter getPublic()
    {
        return publicParam;
    }

    /**
     * 返回密钥对中的私钥部分
     * @return the private key parameters.
     */
    public PairingKeySerParameter getPrivate()
    {
        return privateParam;
    }
}