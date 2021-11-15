package swabe;

import generators.PairingKeyParameterGenerator;
import serparams.PairingKeySerParameter;
import genparams.CPABESecretKeyGenerationParameter;
import utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;


public class SWSecretKeyGenerator implements PairingKeyParameterGenerator {
    private CPABESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        SWMasterSecretKeySerParameter masterSecretKeyParameter = (SWMasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        SWPublicKeySerParameter publicKeyParameter = (SWPublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, Element> D1s = new HashMap<String, Element>();
        Map<String, Element> D2s = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element D = masterSecretKeyParameter.getGAlpha().mul(publicKeyParameter.getG().powZn(r)).powZn(masterSecretKeyParameter.getBeta().invert()).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            D1s.put(attribute, publicKeyParameter.getG().powZn(r).mul(elementAttribute.powZn(ri)).getImmutable());
            D2s.put(attribute, publicKeyParameter.getG().powZn(ri).getImmutable());
        }
            return new SWSecretKeySerParameter(publicKeyParameter.getParameters(), D, D1s, D2s);
    }
}