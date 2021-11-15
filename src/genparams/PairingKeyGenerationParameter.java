package genparams;

import serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * 公/私钥生成器
 */
public class PairingKeyGenerationParameter extends KeyGenerationParameters {
    private PairingKeySerParameter masterSecretKeyParameter;//主密钥
    private PairingKeySerParameter publicKeyParameter;//公钥

    /**
     * 构造函数，使用公钥参数、主密钥参数
     * @param publicKeyParameter
     * @param masterSecretKeyParameter
     */
    public PairingKeyGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter) {
        super(null, PairingParametersGenerationParameter.STENGTH);

        this.masterSecretKeyParameter = masterSecretKeyParameter;
        this.publicKeyParameter = publicKeyParameter;
    }
    
   /**
    * 获得主密钥
    * @return
    */
    public PairingKeySerParameter getMasterSecretKeyParameter() {
        return this.masterSecretKeyParameter;
    }
  /**
   * 获得公钥
   * @return
   */
    public PairingKeySerParameter getPublicKeyParameter() {
        return this.publicKeyParameter;
    }
}
