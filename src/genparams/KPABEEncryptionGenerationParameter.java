package genparams;

import generators.AsymmetricKeySerPairGenerator;
import genparams.PairingEncryptionGenerationParameter;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeySerParameter;
import chameleonhash.ChameleonHasher;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class KPABEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private String[] attributes;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
    private PairingCipherSerParameter intermediate;

    public KPABEEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, String[] attributes, Element message) {
        super(publicKeyParameter, message);
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
        this.chameleonHashKeyPairGenerator = keyPairGenerator;
    }

    public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHashKeyPairGenerationParameter = keyGenerationParameters;
    }

    public void setIntermediate(PairingCipherSerParameter intermediate) {
        this.intermediate = intermediate;
    }

    public String[] getAttributes() { return this.attributes; }

    public ChameleonHasher getChameleonHasher() {
        return this.chameleonHasher;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
        return this.chameleonHashKeyPairGenerationParameter;
    }

    public boolean isIntermediateGeneration() {
        return (this.intermediate != null);
    }

    public PairingCipherSerParameter getIntermediate() {
        return this.intermediate;
    }
}
