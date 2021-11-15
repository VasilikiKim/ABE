package abe;

import generators.PairingKeyPairGenerator;
import serparams.PairingKeySerPair;

import genparams.CPABEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class KeyPairGenerator implements PairingKeyPairGenerator {
    private CPABEKeyPairGenerationParameter parameters;

    /**
     * 初始化
     */
    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

  
    /**
     * 生成公/私钥对
     */
    public PairingKeySerPair generateKeyPair(String[] attributeUniverse) {
        
    	Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element a     = pairing.getZr().newRandomElement().getImmutable();
        
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element ga = g.powZn(a).getImmutable();
        Element gAlpha=g.powZn(alpha).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        
       
        Map<String, Element> h = new HashMap<String, Element>();
         for (String attribute : attributeUniverse) {
        	h.put(attribute, pairing.getG1().newRandomElement().getImmutable());
        }
  
        return new PairingKeySerPair(
                new PublicKeySerParameter(this.parameters.getPairingParameters(),  g,  eggAlpha, ga , h  ),
                new MasterSecretKeySerParameter(this.parameters.getPairingParameters(), gAlpha));
    }
    
    
    
    
    
}
