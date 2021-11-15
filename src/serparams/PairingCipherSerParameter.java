package serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

//密文参数
public class PairingCipherSerParameter implements CipherParameters, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private PairingParameters parameters;//配对参数

	/**
	 * 构造函数
	 * @param parameters
	 */
    public PairingCipherSerParameter(PairingParameters parameters) {
        this.parameters = parameters;
    }

    /**
     * 获得配对参数
     * @return
     */
    public PairingParameters getParameters() {
        return parameters;
    }

    /**
     * 判断两实例是否相等
     */
    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof PairingCipherSerParameter) {
            PairingCipherSerParameter that = (PairingCipherSerParameter)anOjbect;
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
