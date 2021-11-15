package gpswabe;

import generators.PairingEncapsulationPairGenerator;
import generators.PairingEncryptionGenerator;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import genparams.KPABEEncryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;


public class GPSWEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private KPABEEncryptionGenerationParameter params;

    private GPSWPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Map<String, Element> Es;

    public void init(CipherParameters params) {
        this.params = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (GPSWPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.params.getAttributes();
        assert(attributes.length <= publicKeyParameter.getMaxAttributesNum());
        if (attributes.length > publicKeyParameter.getMaxAttributesNum()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + attributes.length +
                    " is greater than the maximal number of receivers " + publicKeyParameter.getMaxAttributesNum());
        }

        try {
            Element s = pairing.getZr().newRandomElement().getImmutable();
            this.sessionKey = publicKeyParameter.getY().powZn(s).getImmutable();
            this.Es = new HashMap<String, Element>();
            for (String attribute : attributes) {
                int index = Integer.parseInt(attribute);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element E = publicKeyParameter.getTsAt(String.valueOf(index)).powZn(s).getImmutable();
                Es.put(String.valueOf(index), E);
            }
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element EPrime = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new GPSWCiphertextSerParameter(publicKeyParameter.getParameters(), EPrime, Es);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new GPSWHeaderSerParameter(publicKeyParameter.getParameters(), Es)
        );
    }
}