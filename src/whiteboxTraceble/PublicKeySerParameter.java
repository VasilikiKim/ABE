package whiteboxTraceble;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import serparams.PairingKeySerParameter;

public class PublicKeySerParameter extends PairingKeySerParameter{
	
	private static final long serrialVersionUID = 1L;
	
	private transient Element N;
	private final byte[] byteArrayN;
	
	private transient Element h;
	private final byte[] byteArrayH;
	
	private transient Element g;
	private final byte[] byteArrayG;
	
	private transient Element g_a;
	private final byte[] byteArrayG_A;
	
	private transient Element eggAlpha;
	private final byte[] byteArrayEggAlpha;
	
	private transient Map<String, Element> U;
	private transient Map<String, byte[]> byteArrayU;
	
	public PublicKeySerParameter (PairingParameters pairingParameters, Element N, Element h ,Element g, Element g_a, Element eggAlpha, Map<String, Element> U) {
		super(true, pairingParameters);
		
		this.N = N.getImmutable();
		this.byteArrayN = this.N.toBytes();
		
		this.h = h.getImmutable();
		this.byteArrayH = this.h.toBytes();
		
		this.g = g.getImmutable();
		this.byteArrayG = this.g.toBytes();
		
		this.g_a = g_a.getImmutable();
		this.byteArrayG_A = this.g_a.toBytes();
		
		this.eggAlpha = eggAlpha;
		this.byteArrayEggAlpha = this.eggAlpha.toBytes();
		
		this.U = new HashMap<String, Element>();
		this.byteArrayU = new HashMap<String, byte[]>();
		
		for (String attribute : U.keySet() ) {
			this.U.put(attribute, U.get(attribute).duplicate().getImmutable());
			this.byteArrayU.put(attribute, U.get(attribute).duplicate().getImmutable().toBytes());
		}
		
		
	}

	public Element getN() {
		return N;
	}

	public void setN(Element n) {
		N = n;
	}

	public Element getH() {
		return h;
	}

	public void setH(Element h) {
		this.h = h;
	}

	public Element getG() {
		return g;
	}

	public Element getEggAlpha() {
		return eggAlpha;
	}

	public Element getG_a() {
		return g_a;
	}

	public Map<String, Element> getU() {
		return U;
	}

}
