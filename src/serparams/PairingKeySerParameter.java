package serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;

/*配对中的密钥参数*/
public class PairingKeySerParameter extends PairingCipherSerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	//是否是私钥
	private boolean privateKey;

	//构造函数
    public PairingKeySerParameter(boolean privateKey, PairingParameters pairingParameters) {
        super(pairingParameters);
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
     * 比较是否两对象是否相等
     */
    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof PairingKeySerParameter) {
            PairingKeySerParameter that = (PairingKeySerParameter)anOjbect;
            //Compare Pairing Parameters
            return (this.privateKey == that.privateKey);
        }
        return false;
    }
}
