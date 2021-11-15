package whiteboxTraceble;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;

import acess.AccessControlEngine;
import acess.AccessControlParameter;
import generators.PairingEncapsulationPairGenerator;
import generators.PairingEncryptionGenerator;
import genparams.CPABEEncryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import serparams.PairingKeyEncapsulationSerPair;

public class EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
	private CPABEEncryptionGenerationParameter parameter;
	
	private PublicKeySerParameter publicKeyParameter;
	private Element sessionKey;
	private Element C0;
	private Element C0_;
	private Map<String, Element> C_i;
	private Map<String, Element> C_i_;
	
	public void init(CipherParameters parameter) {
		this.parameter = (CPABEEncryptionGenerationParameter) parameter;
		this.publicKeyParameter = (PublicKeySerParameter) this.parameter.getPublicKeyParameter();
	}
	
	private void computeEncapsulation() {
		int[][] accessPolicy = this.parameter.getAccessPolicy();
		String[] rhos = this.parameter.getRhos();
		AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
		AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
	
		Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
		Element s = pairing.getZr().newRandomElement().getImmutable();
		this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
		this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
		this.C0_ = publicKeyParameter.getG_a().powZn(s).getImmutable();
		Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
		
		this.C_i = new HashMap<String, Element>();
		this.C_i_ = new HashMap<String, Element>();
		
		for (String rho : lambdas.keySet()) {
			Element r = pairing.getZr().newRandomElement().getImmutable();
			Element CTemp1 = publicKeyParameter.getH().powZn(lambdas.get(rho));
			Element CTemp2 = publicKeyParameter.getU().get(rho).duplicate().powZn(r.negate());
			C_i.put(rho, CTemp1.mul(CTemp2).getImmutable());
			C_i_.put(rho, publicKeyParameter.getG().powZn(r).getImmutable());
		}
		
	}
	
	public CiphertextSerParameter generateCiphertext() {
		computeEncapsulation();
		Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
		return new CiphertextSerParameter(publicKeyParameter.getParameters(),C, C0, C0_,
				C_i, C_i_);
	}
	
	public PairingKeyEncapsulationSerPair generateEncryptionPair() {
		computeEncapsulation();
		return new PairingKeyEncapsulationSerPair(this.sessionKey.toBytes(), 
				new HeaderSerParameter(publicKeyParameter.getParameters(), C0, C0_, C_i, C_i_));
	}
}
