package abe;

import serparams.PairingKeySerParameter;
import utils.PairingUtils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


//Waters-08-CPABE
public class PublicKeySerParameter extends PairingKeySerParameter {
 
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private transient Element g;//生成元
	private final byte[] byteArrayG;
	
	private transient Element eggAlpha;//双线性映射 e(g,g)^{alpha}
	private final byte[] byteArrayEggAlpha;
	
	private transient Element ga;//g^a
	private final byte[] byteArrayGA;
	
	private transient Map<String,Element> h;//h_i与属性域元素一一对应
	private final Map<String,byte[]> byteArraysH;
	
	
	/**
	 * 构造函数
	 * @param pairingParameters
	 * @param g
	 * @param eggAlpha
	 * @param ga
	 * @param h
	 */
    public PublicKeySerParameter(PairingParameters pairingParameters, Element g,Element eggAlpha ,Element ga,  Map<String,Element> h ) {
        super(true, pairingParameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes(); 
        
        this.ga = ga.getImmutable();
        this.byteArrayGA = this.ga.toBytes();

        this.h = new HashMap<String, Element>();
        this.byteArraysH = new HashMap<String, byte[]>();

        for (String attribute : h.keySet()) {
            this.h.put(attribute, h.get(attribute).duplicate().getImmutable());
            this.byteArraysH.put(attribute, h.get(attribute).duplicate().getImmutable().toBytes());
        }
    
    }


   //获取公钥各组成参数
	public Element getG() {return this.g.duplicate();}
    
    public Element getEggAlpha() {return this.eggAlpha.duplicate();}
    
    public Element getGA () {return this.ga.duplicate();}
   
    public Element getHAt(String attribute) { return this.h.get(attribute).duplicate(); }
    

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof PublicKeySerParameter) {
            PublicKeySerParameter that = (PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
                return false;
            }
            //Compare h
            if (!this.h.equals(that.h)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysH, that.byteArraysH)) {
                return false;
            }
            //Compare ga
            if (!PairingUtils.isEqualElement(this.ga, that.ga)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGA, that.byteArrayGA)) {
                return false;
            }
            
          
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
        this.ga = pairing.getG1().newElementFromBytes(this.byteArrayGA).getImmutable();
        this.h = new HashMap<String, Element>();
        for (String attribute : this.byteArraysH.keySet()) {
            this.h.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysH.get(attribute)).getImmutable());
        }
      
    }
	
	
}
