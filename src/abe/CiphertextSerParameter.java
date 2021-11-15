package abe;

import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;


public class CiphertextSerParameter extends HeaderSerParameter {
	  /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private transient Element C;//C
	    private final byte[] byteArrayC;

	    public CiphertextSerParameter(
	            PairingParameters pairingParameters, Element C, Element Cprime,
	            Map<String, Element> C1s, Map<String, Element> D1s) {
	        super(pairingParameters, Cprime, C1s, D1s);

	        this.C = C.getImmutable();
	        this.byteArrayC = this.C.toBytes();
	    }

	    public Element getC() { return this.C.duplicate(); }

	    @Override
	    public boolean equals(Object anObject) {
	        if (this == anObject) {
	            return true;
	        }
	        if (anObject instanceof CiphertextSerParameter) {
	            CiphertextSerParameter that = (CiphertextSerParameter) anObject;
	            return PairingUtils.isEqualElement(this.C, that.C)
	                    && Arrays.equals(this.byteArrayC, that.byteArrayC)
	                    && super.equals(anObject);
	        }
	        return false;
	    }

	    private void readObject(java.io.ObjectInputStream objectInputStream)
	            throws java.io.IOException, ClassNotFoundException {
	        objectInputStream.defaultReadObject();
	        Pairing pairing = PairingFactory.getPairing(this.getParameters());
	        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
	    }
}