package abe;

import generators.PairingKeyParameterGenerator;
import serparams.PairingKeySerParameter;
import genparams.CPABESecretKeyGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;


public class SecretKeyGenerator implements PairingKeyParameterGenerator {
    private CPABESecretKeyGenerationParameter parameter;

    /**
     * 初始化
     */
    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    /**
     * 生成私钥
     * @return
     */
    public PairingKeySerParameter generateKey() {
        MasterSecretKeySerParameter masterSecretKeyParameter = (MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        PublicKeySerParameter publicKeyParameter = (PublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> Kx = new HashMap<String, Element>();
       
        Element K = masterSecretKeyParameter.getGAlpha().mul(publicKeyParameter.getGA().powZn(t)).getImmutable();
        Element L = publicKeyParameter.getG().powZn(t).getImmutable();
       
        for (String attribute : attributes) {
        	Kx.put(attribute, publicKeyParameter.getHAt(attribute).powZn(t).getImmutable());
            
        }
            return new SecretKeySerParameter(publicKeyParameter.getParameters(), K, L,Kx);
    }
}