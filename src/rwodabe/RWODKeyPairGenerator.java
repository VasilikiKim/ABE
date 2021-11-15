package rwodabe;
import generators.PairingKeyPairGenerator2;
import serparams.PairingKeySerPair;
import genparams.CPABEKeyPairGenerationParameter;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class RWODKeyPairGenerator implements PairingKeyPairGenerator2{
	protected CPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element u = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element w = pairing.getG1().newRandomElement().getImmutable();
        Element v = pairing.getG1().newRandomElement().getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new PairingKeySerPair(
                new RWODPublicKeySerParameter(this.parameters.getPairingParameters(), g, u, h, w, v, eggAlpha),
                new RWODMasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha));
    }
}

