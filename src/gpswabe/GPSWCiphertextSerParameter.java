package gpswabe;

import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;


public class GPSWCiphertextSerParameter extends GPSWHeaderSerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private transient Element EPrime;
    private final byte[] byteArrayEPrime;

    public GPSWCiphertextSerParameter(PairingParameters pairingParameters, Element EPrime, Map<String, Element> Es) {
        super(pairingParameters, Es);
        this.EPrime = EPrime.getImmutable();
        this.byteArrayEPrime = this.EPrime.toBytes();
    }

    public Element getEPrime() { return this.EPrime.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GPSWCiphertextSerParameter) {
            GPSWCiphertextSerParameter that = (GPSWCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.EPrime, that.EPrime)
                    && Arrays.equals(this.byteArrayEPrime, that.byteArrayEPrime)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.EPrime = pairing.getGT().newElementFromBytes(this.byteArrayEPrime);
    }
}