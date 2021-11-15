package genparams;

import serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;

//配对加密生成器
public abstract class PairingEncryptionGenerationParameter extends PairingEncapsulationGenerationParameter {
    private Element message;//消息（元素形式）

    /**
     * 构造函数，使用公钥，待加密消息
     * @param publicKeyParameter
     * @param message
     */
    public PairingEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, Element message) {
        super(publicKeyParameter);
        if (message != null) {
            //parameter for encryption.
            this.message = message.getImmutable();
        }
    }

    /**
     * 获得待加密消息
     * @return
     */
    public Element getMessage() {
        if (message == null) {
            return null;
        }
        return this.message.duplicate();
    }
}
