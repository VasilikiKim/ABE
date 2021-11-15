package gpswabe;

import generators.PairingKeyPairGenerator2;
import serparams.PairingKeySerPair;
import genparams.KPABEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;


public class GPSWKeyPairGenerator implements PairingKeyPairGenerator2 {
    private KPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABEKeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Map<String, Element> ts = new HashMap<String, Element>();
        Map<String, Element> Ts = new HashMap<String, Element>();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element Y = pairing.pairing(g, g).powZn(y).getImmutable();
        for (int i = 0; i < this.parameters.getMaxAttributesNum(); i++) {
            String attribute = String.valueOf(i);
            Element t = pairing.getZr().newRandomElement().getImmutable();
            ts.put(attribute, t);
            Ts.put(attribute, g.powZn(t).getImmutable());
        }

        return new PairingKeySerPair(
                new GPSWPublicKeySerParameter(this.parameters.getPairingParameters(), g, Ts, Y),
                new GPSWMasterSecretKeySerParameter(this.parameters.getPairingParameters(), ts, y));
    }
}