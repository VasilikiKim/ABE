package serparams;
import org.bouncycastle.crypto.CipherParameters;
//非对称密钥对（包含公钥和主密钥）
public class AsymmetricKeySerPair {
	 private AsymmetricKeySerParameter publicParam;//公钥参数
	    private AsymmetricKeySerParameter privateParam;//主密钥参数

	    /**
	     * 构造函数
	     * @param publicParam a public key parameters object.
	     * @param privateParam the corresponding private key parameters.
	     */
	    public AsymmetricKeySerPair(AsymmetricKeySerParameter publicParam, AsymmetricKeySerParameter privateParam)
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
	    public AsymmetricKeySerPair(CipherParameters publicParam, CipherParameters privateParam)
	    {
	        this.publicParam = (AsymmetricKeySerParameter)publicParam;
	        this.privateParam = (AsymmetricKeySerParameter)privateParam;
	    }

	    /**
	     * 获得公钥
	     * @return the public key parameters.
	     */
	    public AsymmetricKeySerParameter getPublic()
	    {
	        return publicParam;
	    }

	    /**
	     * 获得主密钥
	     * @return the private key parameters.
	     */
	    public AsymmetricKeySerParameter getPrivate()
	    {
	        return privateParam;
	    }
}
