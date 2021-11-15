package genparams;

import acess.AccessControlEngine;
import generators.AsymmetricKeySerPairGenerator;
import genparams.PairingEncryptionGenerationParameter;
import serparams.PairingCipherSerParameter;
import serparams.PairingKeySerParameter;
import chameleonhash.ChameleonHasher;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * CP-ABE 加密生成器
 * 参数列表：公钥参数、访问控制引擎、访问策略矩阵、属性集合、哈希函数、密文参数
 */
public class CPABEEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;
    private String[] tags;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
    private PairingCipherSerParameter intermediate;

    /**
     * 构造函数
     * @param accessControlEngine
     * @param publicKeyParameter
     * @param accessPolicy
     * @param rhos
     * @param message
     */
    public CPABEEncryptionGenerationParameter(AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter,
                                              int[][] accessPolicy, String[] rhos, Element message) {
        super(publicKeyParameter, message);
        this.accessControlEngine = accessControlEngine;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public void setIntermediate(PairingCipherSerParameter intermediate) {
        this.intermediate = intermediate;
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
        this.chameleonHashKeyPairGenerator = keyPairGenerator;
    }

    public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHashKeyPairGenerationParameter = keyGenerationParameters;
    }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
    
    public String[] getTags() { return this.tags; }
    
    public ChameleonHasher getChameleonHasher() {
        return this.chameleonHasher;
    }

    public boolean isIntermediateGeneration() {
        return (this.intermediate != null);
    }

    public PairingCipherSerParameter getIntermediate() {
        return this.intermediate;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
        return this.chameleonHashKeyPairGenerationParameter;
    }
}