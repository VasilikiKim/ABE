package whiteboxTraceble;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.KeyGenerationParameters;

import generators.PairingKeyParameterGenerator;
import genparams.CPABESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import serparams.PairingKeySerParameter;

public class SecretKeyGenerator implements PairingKeyParameterGenerator{
	
	private CPABESecretKeyGenerationParameter parameter;
	
	public void init(KeyGenerationParameters keyGP) {
		this.parameter = (CPABESecretKeyGenerationParameter)keyGP;
	}
	
	public PairingKeySerParameter generateKey() {
		MasterSecretKeySerParameter masterSecretKeyParameter = (MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
		PublicKeySerParameter publicKeyParameter = (PublicKeySerParameter) parameter.getPublicKeyParameter();
	
		String[] attributes = this.parameter.getAttributes();
		Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
		
		Element R = pairing.getG1().newRandomElement().getImmutable();
		Element R0 = pairing.getG1().newRandomElement().getImmutable();
		Element R0_ = pairing.getG1().newRandomElement().getImmutable();
		Element c = pairing.getZr().newRandomElement().getImmutable();
		Element t = pairing.getZr().newRandomElement().getImmutable(); 
		
		Element KTemp1 = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha().div(masterSecretKeyParameter.getA().add(c)));
		Element KTemp2 = publicKeyParameter.getH().powZn(t);
		
		Element K = KTemp1.mul(KTemp2).mul(R);
		Element K_ = c;
		
		Element L = (publicKeyParameter.getG().powZn(t)).mul(R0);
		Element L_ = (publicKeyParameter.getG_a().powZn(t)).mul(R0_);
		
		Map<String, Element> KX = new HashMap<String, Element>();
		
		for(String attribute : attributes) {
			Element Rx = pairing.getG1().newRandomElement().getImmutable();
			
			Element KXTemp1 = (masterSecretKeyParameter.getA().add(c)).mul(t);
			KX.put(attribute, publicKeyParameter.getU().get(attribute).duplicate().powZn(KXTemp1).mul(Rx).getImmutable());
		}
		
		return new SecretKeySerParameter(publicKeyParameter.getParameters(), K, K_, L, L_, KX);
	}
}
