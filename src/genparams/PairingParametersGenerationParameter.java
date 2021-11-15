package genparams;

import org.bouncycastle.crypto.CipherParameters;

import java.security.SecureRandom;

/**
 *配对参数生成器.
 */
public class PairingParametersGenerationParameter implements CipherParameters {
    // Default strength for KeyPairGenerator, useless in Pairing based cryptography
    private static final int DEFAULT_Q_BIT_LENGTH = 512;
    public static final int STENGTH = DEFAULT_Q_BIT_LENGTH * 2;

    //配对类型
    public enum PairingType {
        TYPE_A, TYPE_A1, TYPE_E, TYPE_F,
    }

    private PairingType pairingType;
    private final int rBitLength;
    private final int qBitLength;
    private final int n;

    /**
     * Type A and Type E 曲线参数
     * @param pairingType PairingType.TYPE_A or PairingType.TYPE_E.
     * @param rBitLength r bit length.
     * @param qBitLength q bit length.
     */
    public PairingParametersGenerationParameter(PairingType pairingType, int rBitLength, int qBitLength) {
        switch (pairingType) {
            case TYPE_A:
            case TYPE_E:
                this.pairingType = pairingType;
                this.rBitLength = rBitLength;
                this.qBitLength = qBitLength;
                this.n = 1;
                break;
            default:
                throw new IllegalArgumentException("Invalid curve type, need TypeA or TypeE");
        }
    }

    /**
     * Type A1 曲线参数.
     * @param n 质因子数量
     * @param qBitLength 每个质数因子q bit 长.
     */
    public PairingParametersGenerationParameter(int n, int qBitLength) {
        this.pairingType = PairingType.TYPE_A1;
        this.rBitLength = qBitLength;
        this.qBitLength = qBitLength;
        this.n = n;
    }

    /**
     * Type F 曲线参数，必须和安全随机数相关
     * @param secureRandom 给出的安全随机数
     * @param rBitLength r bit length for Z_p.
     */
    public PairingParametersGenerationParameter(SecureRandom secureRandom, int rBitLength) {
        this.pairingType = PairingType.TYPE_F;
        this.rBitLength = rBitLength;
        this.qBitLength = rBitLength;
        this.n = 1;
    }

    public int getN() { return this. n; }

    public PairingType getPairingType() { return this.pairingType; }

    public int getQBitLength() {
        return this.qBitLength;
    }

    public int getRBitLength() {
        return this.rBitLength;
    }
}