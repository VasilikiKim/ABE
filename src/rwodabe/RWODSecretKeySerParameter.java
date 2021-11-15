package rwodabe;

import java.util.Arrays;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import serparams.PairingKeySerParameter;
import utils.PairingUtils;

public class RWODSecretKeySerParameter extends PairingKeySerParameter {

	
	private static final long serialVersionUID = 1L;
	private transient Element Z;
	private PairingKeySerParameter TransKey;
	
	 public RWODSecretKeySerParameter(PairingParameters pairingParameters,Element Z, PairingKeySerParameter TransKey)
     {
		 super(true, pairingParameters);
         this.Z = Z;
         this.TransKey = TransKey;
     }
	 
	 public Element getZ()
	    {
	        return this.Z.duplicate();
	    }
	 

	 public PairingKeySerParameter getTransKey()
	    {
	        return this.TransKey;
	    }
	 
	
	
	//private final byte[] byteArrayZ;

   /* public RWODSecretKeySerParameter(PairingParameters pairingParameters, Element Z, Element K0,
    		Element K1, Map<String, Element> K2s, Map<String, Element> K3s) {
        super(pairingParameters, K0, K1, K2s, K3s);

        this.Z = Z.getImmutable();
        this.byteArrayZ = this.Z.toBytes();
    }

    public Element getZ() { return this.Z.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RWODSecretKeySerParameter) {
            RWODSecretKeySerParameter that = (RWODSecretKeySerParameter) anObject;
            return PairingUtils.isEqualElement(this.Z, that.Z)
                    && Arrays.equals(this.byteArrayZ, that.byteArrayZ)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.Z = pairing.getZr().newElementFromBytes(this.byteArrayZ).getImmutable();
    }*/
    
	
}
