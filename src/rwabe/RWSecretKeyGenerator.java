package rwabe;
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
public class RWSecretKeyGenerator implements PairingKeyParameterGenerator {
	protected CPABESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        RWMasterSecretKeySerParameter masterSecretKeyParameter = (RWMasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        RWPublicKeySerParameter publicKeyParameter = (RWPublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Map<String, Element> K2s = new HashMap<String, Element>();
        Map<String, Element> K3s = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element K0 = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha()).mul(publicKeyParameter.getW().powZn(r)).getImmutable();
        Element K1 = publicKeyParameter.getG().powZn(r).getImmutable();

        Element K3Temp = publicKeyParameter.getV().powZn(r.negate()).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            K2s.put(attribute, publicKeyParameter.getG().powZn(ri).getImmutable());
            Element K3i = publicKeyParameter.getU().powZn(elementAttribute).mul(publicKeyParameter.getH()).powZn(ri).getImmutable();
            K3i = K3i.mul(K3Temp).getImmutable();
            K3s.put(attribute, K3i);
        }
        return new RWSecretKeySerParameter(publicKeyParameter.getParameters(), K0, K1, K2s, K3s);
    }
}
