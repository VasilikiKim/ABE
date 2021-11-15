package whiteboxTraceble;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import serparams.PairingKeySerParameter;

public class MasterSecretKeySerParameter extends PairingKeySerParameter{
	
	private static final long serialVersionUID = 1L;
	
	private transient Element alpha;
	private final byte[] byteArrayAlpha;
	
	private transient Element a;
	private final byte[] byteArrayA;
	
	private transient Element X3;
	private final byte[] byteArrayX3;
	
	public MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element a, Element X3) {
		super(true, pairingParameters);
		this.alpha = alpha.getImmutable();
		this.byteArrayAlpha = this.alpha.toBytes();
		
		this.a = a.getImmutable();
		this.byteArrayA = this.a.toBytes();
		
		this.X3 = X3.getImmutable();
		this.byteArrayX3 = this.X3.toBytes();
		
	}

	public Element getAlpha() {
		return alpha;
	}

	public Element getA() {
		return a;
	}
	
	public Element getX3() {
		return X3;
	}	

}
