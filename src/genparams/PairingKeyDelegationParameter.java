package genparams;

import serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

//密钥委托
public class PairingKeyDelegationParameter extends KeyGenerationParameters {
    private PairingKeySerParameter publicKeyParameter;
    private PairingKeySerParameter secretKeyParameter;
    
    /**
     * 构造函数，使用公钥、私钥
     * @param publicKeyParameter
     * @param secretKeyParameter
     */
    public PairingKeyDelegationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.publicKeyParameter = publicKeyParameter;
        this.secretKeyParameter = secretKeyParameter;
    }

    /**
     * 获得公钥
     * @return
     */
    public PairingKeySerParameter getPublicKeyParameter() {
        return this.publicKeyParameter;
    }

    /**
     * 获得私钥
     * @return
     */
    public PairingKeySerParameter getSecretKeyParameter() {
        return this.secretKeyParameter;
    }
}