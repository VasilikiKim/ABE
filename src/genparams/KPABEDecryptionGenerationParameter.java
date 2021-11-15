package genparams;
import acess.AccessControlEngine;
import genparams.PairingDecryptionGenerationParameter;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeySerParameter;
import chameleonhash.ChameleonHasher;
import utils.PairingUtils;


public class KPABEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] attributes;
    private AccessControlEngine accessControlEngine;
    private ChameleonHasher chameleonHasher;

    public KPABEDecryptionGenerationParameter(
            AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] attributes, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.accessControlEngine = accessControlEngine;
        this.attributes = PairingUtils.removeDuplicates(attributes);
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public String[] getAttributes() { return this.attributes; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }

    public ChameleonHasher getChameleonHasher() { return this.chameleonHasher; }
}