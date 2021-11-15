package whiteboxTraceble;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import serparams.PairingKeySerParameter;

public class SecretKeySerParameter extends PairingKeySerParameter{
	
	private static final long serialVersionUID = 1L;
	
	private transient Element K;
	private final byte[] byteArrayK;
		
	private transient Element K_;
	private final byte[] byteArrayK_;
	
	private transient Element L;
	private final byte[] byteArrayL;
	
	private transient Element L_;
	private final byte[] byteArrayL_;
	
	private transient Map<String, Element> Kx;
	private final Map<String, byte[]> byteArrayKx;
	
	public SecretKeySerParameter(PairingParameters pairingParameters, Element K ,Element K_, Element L, Element L_, Map<String, Element> Kx) {
		
		super(true, pairingParameters);
		
		this.K = K.getImmutable();
        this.byteArrayK = this.K.toBytes();
        
        this.K_ =K_.getImmutable();
        this.byteArrayK_ = this.K_.toBytes();

        this.L=L.getImmutable();
        this.byteArrayL=this.L.toBytes();
        
        this.L_=L_.getImmutable();
        this.byteArrayL_=this.L_.toBytes();
        
        this.Kx = new HashMap<String, Element>();
        this.byteArrayKx = new HashMap<String, byte[]>();
	
        for (String attribute : Kx.keySet()) {
            this.Kx.put(attribute, Kx.get(attribute).duplicate().getImmutable());
            this.byteArrayKx.put(attribute, Kx.get(attribute).duplicate().getImmutable().toBytes());
        }
	}

	public Element getK() {
		return K;
	}

	public Element getK_() {
		return K_;
	}

	public Element getL() {
		return L;
	}

	public Element getL_() {
		return L_;
	}

	public Map<String, Element> getKx() {
		return Kx;
	}
	
	 public String[] getAttributes() { return this.Kx.keySet().toArray(new String[1]); }
	
}
