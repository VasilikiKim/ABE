package abe;

import acess.AccessControlEngine;
import acess.AccessControlParameter;
import acess.UnsatisfiedAccessControlException;
import generators.PairingDecapsulationGenerator;
import generators.PairingDecryptionGenerator;

import genparams.CPABEDecryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;


public class DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
	 private CPABEDecryptionGenerationParameter parameter;
	    private Element sessionKey;//会话密钥

	    /**
	     * 初始化
	     */
	    public void init(CipherParameters parameter) {
	        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
	    }

	    /**
	     * 计算解封
	     * @throws InvalidCipherTextException
	     */
	    private void computeDecapsulation() throws InvalidCipherTextException {
	        PublicKeySerParameter publicKeyParameter = (PublicKeySerParameter) this.parameter.getPublicKeyParameter();
	        SecretKeySerParameter secretKeyParameter = (SecretKeySerParameter) this.parameter.getSecretKeyParameter();
	        HeaderSerParameter ciphertextParameter = (HeaderSerParameter) this.parameter.getCiphertextParameter();
	        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
	        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
	        try {
	            AccessControlParameter accessControlParameter
	                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
	            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);
	            Element A = pairing.getGT().newOneElement().getImmutable();
	            for (String attribute : omegaElementsMap.keySet()) {
	                Element L = secretKeyParameter.getL();
	                Element Kx = secretKeyParameter.getKxAt(attribute);
	                Element C1 = ciphertextParameter.getC1sAt(attribute);
	                Element D1 = ciphertextParameter.getD1sAt(attribute);
	                Element lambda = omegaElementsMap.get(attribute);
	                A = A.mul(pairing.pairing(C1, L).mul(pairing.pairing(D1, Kx)).powZn(lambda)).getImmutable();
	            }
	            this.sessionKey = pairing.pairing(ciphertextParameter.getCprime(), secretKeyParameter.getK()).div(A).getImmutable();
	        } catch (UnsatisfiedAccessControlException e) {
	            throw new InvalidCipherTextException("Attributes associated with the secret key do not satisfy access policy associated with the ciphertext.");
	        }
	    }

	    /**
	     * 还原消息
	     */
	    public Element recoverMessage() throws InvalidCipherTextException {
	        computeDecapsulation();
	        CiphertextSerParameter ciphertextParameter = (CiphertextSerParameter) this.parameter.getCiphertextParameter();
	        return ciphertextParameter.getC().div(sessionKey).getImmutable();
	    }

	    /**
	     * 还原会话密钥
	     */
	    public byte[] recoverKey() throws InvalidCipherTextException {
	        computeDecapsulation();
	        return this.sessionKey.toBytes();
	    }
}