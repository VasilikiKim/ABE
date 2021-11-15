package genparams;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * 
 */
public class PairingKeyPairGenerationParameter extends KeyGenerationParameters {
    private PairingParameters pairingParameters;//配对参数

    /**
     * 构造函数，使用配对参数
     * @param pairingParameters
     */
    public PairingKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.pairingParameters = pairingParameters;
    }

    /**
     * 获得配对参数
     * @return
     */
    public PairingParameters getPairingParameters() { return this.pairingParameters; }
}