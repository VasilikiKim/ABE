package abe;

import serparams.PairingKeySerParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class MasterSecretKeySerParameter extends PairingKeySerParameter {

	/**
	 * 主密钥
	 */
	private static final long serialVersionUID = 1L;
	private transient Element gAlpha;//g^{alpha}
    private final byte[] byteArrayGAlpha;
    
    /**
     * 构造函数
     * @param pairingParameters
     * @param gAlpha
     */
    public MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha) {
        super(true, pairingParameters);
        this.gAlpha = gAlpha.getImmutable();
        this.byteArrayGAlpha = this.gAlpha.toBytes();

    }
    
    /**
     * 获得g^{alpha}
     * @return
     */
    public Element getGAlpha() { return this.gAlpha.duplicate(); }

   
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof MasterSecretKeySerParameter) {
            MasterSecretKeySerParameter that = (MasterSecretKeySerParameter)anObject;
            //compare gAlpha
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.gAlpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGAlpha, that.byteArrayGAlpha)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.gAlpha = pairing.getG1().newElementFromBytes(this.byteArrayGAlpha).getImmutable();
        
    }

}
