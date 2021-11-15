package genparams;

import generators.AsymmetricKeySerPairGenerator;
import genparams.PairingEncapsulationGenerationParameter;
import serparams.PairingKeySerParameter;
import chameleonhash.ChameleonHasher;
import org.bouncycastle.crypto.KeyGenerationParameters;


public class KPABEIntermediateGenerationParameter extends PairingEncapsulationGenerationParameter {
    private int n;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyGenerationParameter;

    public KPABEIntermediateGenerationParameter(PairingKeySerParameter publicKeyParameter, int n) {
        super(publicKeyParameter);
        this.n = n;
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
        this.chameleonHashKeyPairGenerator = keyPairGenerator;
    }

    public void setChameleonHashKeyGenerationParameter(KeyGenerationParameters keyGenerationParameter) {
        this.chameleonHashKeyGenerationParameter = keyGenerationParameter;
    }

    public ChameleonHasher getChameleonHasher() {
        return this.chameleonHasher;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyGenerationParameter() {
        return this.chameleonHashKeyGenerationParameter;
    }

    public int getN() {
        return this.n;
    }
}