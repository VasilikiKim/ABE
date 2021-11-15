package swabe;

import generators.PairingKeyPairGenerator2;
import genparams.CPABEKeyPairGenerationParameter;
import serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;


public class SWKeyPairGenerator implements PairingKeyPairGenerator2 {
    private CPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = g.powZn(beta).getImmutable();
        Element f = g.powZn(beta.invert()).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new PairingKeySerPair(
                new SWPublicKeySerParameter(this.parameters.getPairingParameters(), g, h, f, eggAlpha),
                new SWMasterSecretKeySerParameter(this.parameters.getPairingParameters(), gAlpha, beta));
    }
}