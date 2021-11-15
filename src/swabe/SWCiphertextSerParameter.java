package swabe;

import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;


public class SWCiphertextSerParameter extends SWHeaderSerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private transient Element CPrime;
    private final byte[] byteArrayCPrime;

    public SWCiphertextSerParameter(
            PairingParameters pairingParameters, Element CPrime, Element C,
            Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters, C, C1s, C2s);

        this.CPrime = CPrime.getImmutable();
        this.byteArrayCPrime = this.CPrime.toBytes();
    }

    public Element getCPrime() { return this.CPrime.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof SWCiphertextSerParameter) {
            SWCiphertextSerParameter that = (SWCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.CPrime, that.CPrime)
                    && Arrays.equals(this.byteArrayCPrime, that.byteArrayCPrime)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.CPrime = pairing.getGT().newElementFromBytes(this.byteArrayCPrime).getImmutable();
    }
}