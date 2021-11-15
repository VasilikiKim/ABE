package gpswabe;

import acess.AccessControlParameter;
import generators.PairingKeyParameterGenerator;
import serparams.PairingKeySerParameter;
import genparams.KPABESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;


public class GPSWSecretKeyGenerator implements PairingKeyParameterGenerator {
    private KPABESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (KPABESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        GPSWMasterSecretKeySerParameter masterSecretKeyParameter = (GPSWMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        GPSWPublicKeySerParameter publicKeyParameter = (GPSWPublicKeySerParameter)parameters.getPublicKeyParameter();
        assert(parameters.getRhos().length <= publicKeyParameter.getMaxAttributesNum());
        int[][] accessPolicy = this.parameters.getAccessPolicy();
        String[] stringRhos = this.parameters.getRhos();
        Map<String, Element> Ds = new HashMap<String, Element>();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Element y = masterSecretKeyParameter.getY().getImmutable();
            AccessControlParameter accessControlParameter =
                    this.parameters.getAccessControlEngine().generateAccessControl(accessPolicy, stringRhos);
            Map<String, Element> lambdaElementsMap = this.parameters.getAccessControlEngine().secretSharing(pairing, y, accessControlParameter);
            for (String rho : lambdaElementsMap.keySet()) {
                int index = Integer.parseInt(rho);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element d = publicKeyParameter.getG().powZn(lambdaElementsMap.get(rho).div(masterSecretKeyParameter.getTsAt(String.valueOf(index)))).getImmutable();
                Ds.put(String.valueOf(index), d);
            }
            return new GPSWSecretKeySerParameter(publicKeyParameter.getParameters(), accessControlParameter, Ds);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}