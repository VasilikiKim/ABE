package rwabe;
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

public class RWDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator{
	protected CPABEDecryptionGenerationParameter parameter;
    protected Element sessionKey;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        RWPublicKeySerParameter publicKeyParameter = (RWPublicKeySerParameter) this.parameter.getPublicKeyParameter();
        RWSecretKeySerParameter secretKeyParameter = (RWSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        RWHeaderSerParameter ciphertextParameter = (RWHeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        
        
        
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);

            this.sessionKey = pairing.pairing(ciphertextParameter.getC0(), secretKeyParameter.getK0());
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element K1 = secretKeyParameter.getK1();
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element K2 = secretKeyParameter.getK2sAt(attribute);
                Element C3 = ciphertextParameter.getC3sAt(attribute);
                Element K3 = secretKeyParameter.getK3sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(C1, K1).mul(pairing.pairing(C2, K2)).mul(pairing.pairing(C3, K3)).powZn(lambda)).getImmutable();
            }
            sessionKey = sessionKey.div(A).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        RWCiphertextSerParameter ciphertextParameter = (RWCiphertextSerParameter) this.parameter.getCiphertextParameter();
            return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
