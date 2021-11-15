package genparams;

import generators.AsymmetricKeySerPairGenerator;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 
 * CP-ABE 公/私钥对生成器参数.
 */
public class CPABEKeyPairGenerationParameter extends PairingKeyPairGenerationParameter {
    private int maxAttributesNum;//最大属性数
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;//生成器
    private KeyGenerationParameters chameleonHashKeyGenerationParameter;//生成参数

    /**
     * 构造函数，使用配对参数，最大属性数置-1
     * @param pairingParameters
     */
    public CPABEKeyPairGenerationParameter(PairingParameters pairingParameters) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
    }
    
   /**
    * 构造函数，使用配对参数和最大属性数
    * @param pairingParameters
    * @param maxAttributesNum
    */
    public CPABEKeyPairGenerationParameter(PairingParameters pairingParameters, int maxAttributesNum) {
        super(pairingParameters);
        this.maxAttributesNum = maxAttributesNum;
    }

    /**
     * 构造函数，使用配对参数、密钥对生成器和密钥生成器参数
     * @param pairingParameters
     * @param chameleonHashKeyPairGenerator
     * @param chameleonHashKeyGenerationParameter
     */
    public CPABEKeyPairGenerationParameter(
            PairingParameters pairingParameters,
            AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator,
            KeyGenerationParameters chameleonHashKeyGenerationParameter) {
        super(pairingParameters);
        this.maxAttributesNum = -1;
        this.chameleonHashKeyPairGenerator = chameleonHashKeyPairGenerator;
        this.chameleonHashKeyGenerationParameter = chameleonHashKeyGenerationParameter;
    }

    /**
     * 获得最大属性数
     * @return
     */
    public int getMaxAttributesNum() {
        return this.maxAttributesNum;
    }

    /**
     * 设置最大属性数
     * @param maxAttributesNum
     * @return
     */
    public int setMaxAttributesNum(int maxAttributesNum) {
         this.maxAttributesNum=maxAttributesNum;
         return 0;
    }
    
    /**
     * 获得生成器
     * @return
     */
    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    /**
     * 获得生成器参数
     * @return
     */
    public KeyGenerationParameters getChameleonHashKeyGenerationParameter() {
        return this.chameleonHashKeyGenerationParameter;
    }
}