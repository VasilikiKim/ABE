package gpswabe;

import serparams.PairingCipherSerParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;


public class GPSWHeaderSerParameter extends PairingCipherSerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final String[] attributes;
    private transient Map<String, Element> Es;
    private final byte[][] byteArraysEs;

    public GPSWHeaderSerParameter(PairingParameters pairingParameters, Map<String, Element> Es) {
        super(pairingParameters);

        this.Es = new HashMap<String, Element>();
        this.attributes = Es.keySet().toArray(new String[1]);
        this.byteArraysEs = new byte[this.attributes.length][];
        for (int i = 0; i < this.attributes.length; i++) {
            Element E = Es.get(this.attributes[i]).duplicate().getImmutable();
            this.Es.put(this.attributes[i], E);
            this.byteArraysEs[i] = E.toBytes();
        }
    }

    public Element getEsAt(String attribute) { return this.Es.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GPSWHeaderSerParameter) {
            GPSWHeaderSerParameter that = (GPSWHeaderSerParameter)anObject;
            //Compare Es
            if (!this.Es.equals(that.Es)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysEs, that.byteArraysEs)) {
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
        this.Es = new HashMap<String, Element>();
        for (int i = 0; i < this.attributes.length; i++) {
            this.Es.put(attributes[i], pairing.getG1().newElementFromBytes(this.byteArraysEs[i]).getImmutable());
        }
    }
}