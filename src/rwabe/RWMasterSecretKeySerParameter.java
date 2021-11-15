package rwabe;

import serparams.PairingKeySerParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class RWMasterSecretKeySerParameter  extends PairingKeySerParameter {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private transient Element alpha;
    private final byte[] byteArrayAlpha;

    public RWMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.byteArrayAlpha = this.alpha.toBytes();
    }

    public Element getAlpha() { return this.alpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RWMasterSecretKeySerParameter) {
            RWMasterSecretKeySerParameter that = (RWMasterSecretKeySerParameter)anObject;
            //compare alpha
            if (!(PairingUtils.isEqualElement(this.alpha, that.alpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)) {
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
        this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
    }
}
