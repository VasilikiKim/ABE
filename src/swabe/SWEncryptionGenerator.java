package swabe;

import acess.AccessControlEngine;
import acess.AccessControlParameter;
import generators.PairingEncapsulationPairGenerator;
import generators.PairingEncryptionGenerator;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeyEncapsulationSerPair;
import genparams.CPABEEncryptionGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;


public class SWEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private CPABEEncryptionGenerationParameter parameter;

    private SWPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element C;
    private Map<String, Element> C1s;
    private Map<String, Element> C2s;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (SWPublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C = publicKeyParameter.getH().powZn(s).getImmutable();
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            C1s.put(rho, publicKeyParameter.getG().powZn(lambdas.get(rho)).getImmutable());
            C2s.put(rho, PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1).powZn(lambdas.get(rho)).getImmutable());
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element CPrime = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new SWCiphertextSerParameter(publicKeyParameter.getParameters(), CPrime, C, C1s, C2s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new SWHeaderSerParameter(publicKeyParameter.getParameters(), C, C1s, C2s)
        );
    }
}