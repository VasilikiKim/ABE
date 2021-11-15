package swabe;

import serparams.PairingKeySerParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;


public class SWPublicKeySerParameter extends PairingKeySerParameter {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element f;
    private final byte[] byteArrayF;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public SWPublicKeySerParameter(PairingParameters parameters, Element g, Element h, Element f, Element eggAlpha) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();

        this.f = f.getImmutable();
        this.byteArrayF = this.f.toBytes();

        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof SWPublicKeySerParameter) {
            SWPublicKeySerParameter that = (SWPublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.h)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare f
            if (!PairingUtils.isEqualElement(this.f, that.f)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayF, that.byteArrayF)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
        this.f = pairing.getGT().newElementFromBytes(this.byteArrayF).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}