package rwodabe;

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

public class RWODDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator{
	protected CPABEDecryptionGenerationParameter parameter;
    protected Element decryptedCipher;
    
    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    protected void computeTransform() throws InvalidCipherTextException {
       System.out.println("进行密文转换");
    	RWODPublicKeySerParameter publicKeyParameter = (RWODPublicKeySerParameter) this.parameter.getPublicKeyParameter();
        RWODSecretKeySerParameter secretKeyParameter = (RWODSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        //
        RWODTransKeySerParameter transKeyParameter=(RWODTransKeySerParameter) secretKeyParameter.getTransKey();
        //
        RWODHeaderSerParameter ciphertextParameter = (RWODHeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            
            //Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);
            //this.decryptedCipher = pairing.pairing(ciphertextParameter.getC0(), secretKeyParameter.getK0());
            
            
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, transKeyParameter.getAttributes(), accessControlParameter);
            this.decryptedCipher = pairing.pairing(ciphertextParameter.getC0(), transKeyParameter.getK0());
            
            
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
               
            	Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element K1 = transKeyParameter.getK1();
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element K2 = transKeyParameter.getK2sAt(attribute);
                Element C3 = ciphertextParameter.getC3sAt(attribute);
                Element K3 = transKeyParameter.getK3sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
            	
            	/*
            	Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element K1 = secretKeyParameter.getK1();
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element K2 = secretKeyParameter.getK2sAt(attribute);
                Element C3 = ciphertextParameter.getC3sAt(attribute);
                Element K3 = secretKeyParameter.getK3sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                */
                
                
                A = A.mul(pairing.pairing(C1, K1).mul(pairing.pairing(C2, K2)).mul(pairing.pairing(C3, K3)).powZn(lambda)).getImmutable();
            }
            decryptedCipher = decryptedCipher.div(A).getImmutable();
            System.out.println("中间密文： "+decryptedCipher.toString());  
            System.out.print("\n");
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeTransform();
        RWODSecretKeySerParameter secretKeyParameter = (RWODSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        RWODCiphertextSerParameter ciphertextParameter = (RWODCiphertextSerParameter) this.parameter.getCiphertextParameter();
        //System.out.println("executes Decrypt-out! ");    
        return ciphertextParameter.getC().div(decryptedCipher.powZn(secretKeyParameter.getZ())).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeTransform();
        return this.decryptedCipher.toBytes();
    }
}
