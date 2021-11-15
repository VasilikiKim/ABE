package rwodabe;
import generators.PairingKeyParameterGenerator;
import serparams.PairingKeySerParameter;
import genparams.CPABESecretKeyGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

public class RWODSecretKeyGenerator implements PairingKeyParameterGenerator {
	protected CPABESecretKeyGenerationParameter parameter;

	private Element K0;
	private Element K1;
    private Map<String, Element> K2s;
    private Map<String, Element> K3s;
	
	
	
    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public void generateKey() {
        RWODMasterSecretKeySerParameter masterSecretKeyParameter = (RWODMasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        RWODPublicKeySerParameter publicKeyParameter = (RWODPublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        
        this.K2s = new HashMap<String, Element>();
        this.K3s = new HashMap<String, Element>();
        
        Element r = pairing.getZr().newRandomElement().getImmutable();
        this.K0 = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha()).mul(publicKeyParameter.getW().powZn(r)).getImmutable();
        this.K1 = publicKeyParameter.getG().powZn(r).getImmutable();

        Element K3Temp = publicKeyParameter.getV().powZn(r.negate()).getImmutable();
        
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            K2s.put(attribute, publicKeyParameter.getG().powZn(ri).getImmutable());
            Element K3i = publicKeyParameter.getU().powZn(elementAttribute).mul(publicKeyParameter.getH()).powZn(ri).getImmutable();
            K3i = K3i.mul(K3Temp).getImmutable();
            K3s.put(attribute, K3i);
        }
        //return new RWODTransKeySerParameter(publicKeyParameter.getParameters(), K0, K1, K2s, K3s);
    }
    
    public RWODSecretKeySerParameter generateKeyOut() {
    	
    	RWODPublicKeySerParameter publicKeyParameter = (RWODPublicKeySerParameter)parameter.getPublicKeyParameter();
    	String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        
        Element Z = pairing.getZr().newRandomElement().getImmutable();
    	generateKey();
    	
    	this.K0=K0.powZn(Z.invert());
    	this.K1=K1.powZn(Z.invert());
    	 for (String attribute : attributes) {
    		 Element K2i=this.K2s.get(attribute).powZn(Z.invert());
    		 this.K2s.put(attribute, K2i);
    		 Element K3i=this.K3s.get(attribute).powZn(Z.invert());
    		 this.K3s.put(attribute, K3i);	    
         }
    	
    	return new RWODSecretKeySerParameter(publicKeyParameter.getParameters(),Z,new  RWODTransKeySerParameter(publicKeyParameter.getParameters(), K0, K1, K2s, K3s));
    }
    
    
    
    
}

