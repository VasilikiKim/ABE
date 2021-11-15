package whiteboxTraceble;


import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.KeyGenerationParameters;

import generators.PairingKeyPairGenerator;
import genparams.CPABEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import serparams.PairingKeySerPair;

public class KeyPairGenerator implements PairingKeyPairGenerator{

		private CPABEKeyPairGenerationParameter parameters; 

		public void init(KeyGenerationParameters keyGenerationParameter) {
			this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
		}
		
		public PairingKeySerPair generateKeyPair(String[] attributeUniverse) {
			
			
			Map<String, Element> U = new HashMap<String, Element>();
			Pairing pairing = PairingFactory.getPairing(parameters.getPairingParameters());
			
			Element alpha = pairing.getZr().newRandomElement().getImmutable();
			Element a = pairing.getZr().newRandomElement().getImmutable();
			
			Element N = pairing.getG1().newRandomElement().getImmutable();
			Element h = pairing.getG1().newRandomElement().getImmutable();
			Element g = pairing.getG1().newRandomElement().getImmutable();
			Element g_a = g.powZn(a);
			Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
			
			Element X3 = pairing.getG1().newRandomElement().getImmutable();
			for(String attribute : attributeUniverse) {
				U.put(attribute, g.powZn(pairing.getZr().newRandomElement().getImmutable()));
			}
			
			return new PairingKeySerPair(
					new PublicKeySerParameter(this.parameters.getPairingParameters(), N, h, g, g_a, eggAlpha, U ), 
					new MasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha, a, X3));
		
		}
}
