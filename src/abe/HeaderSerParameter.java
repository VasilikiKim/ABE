package abe;

import serparams.PairingCipherSerParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


public class HeaderSerParameter extends PairingCipherSerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private final String[] rhos;//密文属性集
    private transient Element Cprime;//C'
    private final byte[] byteArrayCprime;

    private transient Map<String, Element> C1s;//C1i
    private final byte[][] byteArraysC1s;

    private transient Map<String, Element> D1s;//D1i
    private final byte[][] byteArraysD1s;

    /**
     * 构造函数
     * @param pairingParameters
     * @param Cprime
     * @param C1s
     * @param D1s
     */
    public HeaderSerParameter(
            PairingParameters pairingParameters, Element Cprime,
            Map<String, Element> C1s, Map<String, Element> D1s) {
        super(pairingParameters);

        this.rhos = C1s.keySet().toArray(new String[1]);
        this.Cprime = Cprime.getImmutable();
        this.byteArrayCprime = this.Cprime.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new byte[this.rhos.length][];
        this.D1s = new HashMap<String, Element>();
        this.byteArraysD1s = new byte[this.rhos.length][];

        for (int i = 0; i < this.rhos.length; i++) {
            Element C1 = C1s.get(this.rhos[i]).duplicate().getImmutable();
            this.C1s.put(this.rhos[i], C1);
            this.byteArraysC1s[i] = C1.toBytes();

            Element D1 = D1s.get(this.rhos[i]).duplicate().getImmutable();
            this.D1s.put(this.rhos[i], D1);
            this.byteArraysD1s[i] = D1.toBytes();
        }
    }

    /**
     * 获取组成参数
     * @return
     */
    public Element getCprime() { return this.Cprime.duplicate(); }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Element getD1sAt(String rho) { return this.D1s.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HeaderSerParameter) {
            HeaderSerParameter that = (HeaderSerParameter)anObject;
            //Compare Cprime
            if (!PairingUtils.isEqualElement(this.Cprime, that.Cprime)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayCprime, that.byteArrayCprime)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare D1s
            if (!this.D1s.equals(that.D1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysD1s, that.byteArraysD1s)) {
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
        this.Cprime = pairing.getG1().newElementFromBytes(this.byteArrayCprime).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.D1s = new HashMap<String, Element>();
        for (int i = 0; i < this.rhos.length; i++) {
            this.C1s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC1s[i]).getImmutable());
            this.D1s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysD1s[i]).getImmutable());
        }
    }
}