package genparams;

import serparams.PairingKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Pairing key encapsulation generation parameter.
 */
public abstract class PairingEncapsulationGenerationParameter implements CipherParameters {
    private PairingKeySerParameter publicKeyParameter;

    public PairingEncapsulationGenerationParameter(PairingKeySerParameter publicKeyParameter) {
        this.publicKeyParameter = publicKeyParameter;
    }

    public PairingKeySerParameter getPublicKeyParameter() { return this.publicKeyParameter; }
}