package genparams;


import serparams.PairingKeySerParameter;
import utils.PairingUtils;


/**
 * CP-ABE 私钥生成器参数
 */
public class CPABESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] attributes;//用户属性集

    /**
     * 构造函数
     * @param publicKeyParameter
     * @param masterSecretKeyParameter
     * @param attributes
     */
    public CPABESecretKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String[] attributes) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }
    /**
     * 获得属性集合
     * @return
     */
    public String[] getAttributes() { return this.attributes; }
}