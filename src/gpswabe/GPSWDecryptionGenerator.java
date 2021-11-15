package gpswabe;

import acess.AccessControlEngine;
import acess.AccessControlParameter;
import acess.UnsatisfiedAccessControlException;
import generators.PairingDecapsulationGenerator;
import generators.PairingDecryptionGenerator;
import genparams.KPABEDecryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.InvalidParameterException;
import java.util.Map;


public class GPSWDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private KPABEDecryptionGenerationParameter params;
    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (KPABEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        GPSWPublicKeySerParameter publicKeyParameter = (GPSWPublicKeySerParameter)this.params.getPublicKeyParameter();
        GPSWSecretKeySerParameter secretKeyParameter = (GPSWSecretKeySerParameter)this.params.getSecretKeyParameter();
        GPSWHeaderSerParameter ciphertextParameter = (GPSWHeaderSerParameter)this.params.getCiphertextParameter();
        AccessControlParameter accessControlParameter = secretKeyParameter.getAccessControlParameter();
        AccessControlEngine accessControlEngine = this.params.getAccessControlEngine();
        String[] attributes = this.params.getAttributes();
        assert(attributes.length <= publicKeyParameter.getMaxAttributesNum());
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributes, accessControlParameter);
            this.sessionKey = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                int index = Integer.parseInt(attribute);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element D = secretKeyParameter.getDsAt(String.valueOf(index));
                Element E = ciphertextParameter.getEsAt(String.valueOf(index));
                Element lambda = omegaElementsMap.get(attribute);
                sessionKey = sessionKey.mul(pairing.pairing(D, E).powZn(lambda)).getImmutable();
            }
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        GPSWCiphertextSerParameter ciphertextParameter = (GPSWCiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getEPrime().div(this.sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}