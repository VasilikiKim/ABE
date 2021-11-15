package whiteboxTraceble;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import serparams.PairingCipherSerParameter;

public class HeaderSerParameter extends PairingCipherSerParameter{
	
	private static final long serialVersionUID = 1L;
	private final String[] rhos;
	private transient Element C_0;
	private final byte[] byteArrayC_0;
	
	private transient Element C_0_;
	private final byte[] byteArrayC_0_;
	
	private transient Map<String, Element> C_i;
	private final byte[][] byteArrayC_i;
	
	private transient Map<String, Element> C_i_;
	private final byte[][] byteArrayC_i_;
	
	public HeaderSerParameter(
			PairingParameters pairingParameters, Element C_0, Element C_0_, 
			Map<String, Element> C_i, Map<String, Element> C_i_) {
		super(pairingParameters);
		
		this.rhos = C_i.keySet().toArray(new String[1]);
		this.C_0 = C_0.getImmutable();
		this.byteArrayC_0 = this.C_0.toBytes();
		
		this.C_0_ = C_0_.getImmutable();
		this.byteArrayC_0_ = this.C_0_.toBytes();
		this.byteArrayC_i = new byte[this.rhos.length][];
		this.byteArrayC_i_ = new byte[this.rhos.length][];
		
		this.C_i = new HashMap<String, Element>();
		this.C_i_ = new HashMap<String, Element>();
		
		for (int i = 0; i<rhos.length; i++) {
			Element C_i_temp1 = C_i.get(this.rhos[i]).duplicate().getImmutable();
			this.C_i.put(this.rhos[i], C_i_temp1);
			this.byteArrayC_i[i] = C_i_temp1.toBytes();
			
			Element C_i_temp2 = C_i_.get(this.rhos[i]).duplicate().getImmutable();
			this.C_i_.put(this.rhos[i], C_i_temp2);
			this.byteArrayC_i_[i] = C_i_temp2.toBytes();
			
		}
	}

	public Element getC_0() {
		return C_0;
	}

	public Element getC_0_() {
		return C_0_;
	}
	public Map<String, Element> getC_i() {
		return C_i;
	}

	public Map<String, Element> getC_i_() {
		return C_i_;
	}

	public String[] getRhos() {
		return rhos;
	}
	
	
}
