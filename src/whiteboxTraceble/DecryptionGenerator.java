package whiteboxTraceble;

import java.util.Map;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import acess.AccessControlEngine;
import acess.AccessControlParameter;
import acess.UnsatisfiedAccessControlException;
import generators.PairingDecapsulationGenerator;
import generators.PairingDecryptionGenerator;
import genparams.CPABEDecryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator{
	
	private CPABEDecryptionGenerationParameter parameter;
	
	private Element sessionKey;
	
	public void init(CipherParameters parameter) {
		this.parameter = (CPABEDecryptionGenerationParameter) parameter;
	}
	
	private void computeDecapsulation() throws InvalidCipherTextException {
        PublicKeySerParameter publicKeyParameter = (PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        SecretKeySerParameter secretKeyParameter = (SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        HeaderSerParameter ciphertextParameter = (HeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
	
        try {
        	AccessControlParameter accessControlParameter
            = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            
            Map<String, Element> omegaMap =  accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);
        
            Element D = pairing.getGT().newOneElement().getImmutable();
            Element E = pairing.getGT().newOneElement().getImmutable();
            Element K = secretKeyParameter.getK();
        	Element K_ = secretKeyParameter.getK_();
        	Element L = secretKeyParameter.getL();
        	Element L_ = secretKeyParameter.getL_();
        	Element C0 = ciphertextParameter.getC_0();
        	Element C0_ = ciphertextParameter.getC_0_();
            for (String attribute : omegaMap.keySet()) {
            	
            	Element Ci = ciphertextParameter.getC_i().get(attribute);
            	Element Kp = secretKeyParameter.getKx().get(attribute);
            	Element Ci_ = ciphertextParameter.getC_i_().get(attribute);
            	Element lambda = omegaMap.get(attribute);
            	
            	Element DTemp_1 = L.powZn(K_).getImmutable();
            	Element DTemp0 = DTemp_1.mul(L_).getImmutable();
            	Element DTemp1 = pairing.pairing(DTemp0, Ci).getImmutable();
            	Element DTemp2 = pairing.pairing(Kp, Ci_).getImmutable();
            	Element DTemp3 = (DTemp1.mul(DTemp2)).powZn(lambda).getImmutable();
            	D = D.mul(DTemp3).getImmutable();
            	E = E.mul(pairing.pairing(K, (C0.powZn(K_)).mul(C0_))).getImmutable();
            }
            this.sessionKey = D.div(E).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
        	throw new InvalidCipherTextException("Attributes associated with the secret key do not satisfy access policy associated with the ciphertext.");
        }
	}
        public Element recoverMessage() throws InvalidCipherTextException {
        	computeDecapsulation();
        	CiphertextSerParameter cipherText =  (CiphertextSerParameter) this.parameter.getCiphertextParameter();
        	return cipherText.getC().mul(sessionKey).getImmutable();
        }
        
        public byte[] recoverKey() throws InvalidCipherTextException {
        	computeDecapsulation();
        	return this.sessionKey.toBytes();
        }
	
}
