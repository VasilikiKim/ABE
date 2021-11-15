package acess;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Map;


public interface AccessControlEngine {//访问控制接口
    String getEngineName();

    boolean isSupportThresholdGate();//是否支持阈值门

    AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos);//生成访问控制

    Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter);//秘密分享

    Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException;
    

}