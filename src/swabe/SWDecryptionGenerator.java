package swabe;

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

public class SWDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private CPABEDecryptionGenerationParameter parameter;
    private Element sessionKey;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        SWPublicKeySerParameter publicKeyParameter = (SWPublicKeySerParameter) this.parameter.getPublicKeyParameter();
        SWSecretKeySerParameter secretKeyParameter = (SWSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        SWHeaderSerParameter ciphertextParameter = (SWHeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element D1 = secretKeyParameter.getD1sAt(attribute);
                Element D2 = secretKeyParameter.getD2sAt(attribute);
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(D1, C1).div(pairing.pairing(D2, C2)).powZn(lambda)).getImmutable();
            }
            this.sessionKey = pairing.pairing(ciphertextParameter.getC(), secretKeyParameter.getD()).div(A).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        SWCiphertextSerParameter ciphertextParameter = (SWCiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getCPrime().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}