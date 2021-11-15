package whiteboxTraceble;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

public class CiphertextSerParameter extends HeaderSerParameter{
	
	private static final long serialVersionUID = 1L;
	
	private transient Element C;
	private final byte[] byteArrayC;
	
	public CiphertextSerParameter(
			PairingParameters pairingParameters, Element C, Element C_0, Element C_0_,
			Map<String, Element> C_i, Map<String, Element> C_i_
			) {
		super(pairingParameters, C_0, C_0_, 
				C_i, C_i_);
		
		this.C = C.getImmutable();
		this.byteArrayC = this.C.toBytes();
	}
	
	public Element getC() {
		return this.C.duplicate();
	}
}
