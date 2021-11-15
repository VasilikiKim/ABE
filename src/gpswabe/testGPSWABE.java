package gpswabe;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.InvalidCipherTextException;

import acess.ParserUtils;
import acess.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import serparams.PairingKeySerPair;
import serparams.PairingKeySerParameter;
import utils.PairingUtils;
import utils.PairingUtils.PairingGroupType;

public class testGPSWABE {
	private static void testGPSWABE() {
	 GPSWEngine abe=new GPSWEngine();
	 
	 //设置配对类型
	 int rBits = 160; //群的阶
	 int qBits = 512; // zq的阶。
	 TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits); //指定椭圆曲线的种类 typeA
	 PairingParameters typeAParams = pg.generate();
	
	
	 
	 //属性域
	// String[] attributeUniverse= {"合工大","宣城校区","翡翠湖校区","计算机学院","机械工程学院","车辆工程学院"};
	 //属性数目上限
	 int maxNumAttributes=100;
	 
	 //SetUp算法
	 PairingKeySerPair KeyPair=abe.setup(typeAParams, maxNumAttributes);
	
	 //访问策略
	 String AccessPolicy="(11 AND (22 OR (33 AND 44 )))";
	 int[][] accesspolicy = null;
	 
	 //生成策略矩阵
	 try {
		 accesspolicy=ParserUtils.GenerateAccessPolicy(AccessPolicy);
	} catch (PolicySyntaxException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 //密钥属性
	 String[] rhos=new String[accesspolicy.length];
	 try {
		rhos=ParserUtils.GenerateRhos(AccessPolicy);
	} catch (PolicySyntaxException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}

	 /*print*/
	 System.out.println("访问控制策略："+AccessPolicy);
	 System.out.println("访问控制结构：");
     for(int i=0;i<accesspolicy.length;i++) {
		 for(int j=0;j<accesspolicy[i].length;j++)
		 {
			 System.out.print(accesspolicy[i][j]+"\t");
		 }
		 System.out.print("\n");
	 }
     /*print*/
     
	 
     //明文
	 String message= "Ciphertext-policy attribute-based encryption: An expressive, efficient, and provably secure realization";
	 Element elementMessage=PairingUtils.MapStringToGroup(PairingFactory.getPairing(typeAParams), message, PairingGroupType.GT).getImmutable();
	 Map<Element,String> PT=new HashMap<Element,String >();
	 PT.put(elementMessage,message);
	 System.out.println("明文："+message);
	 
	 //Key Generation算法
	 PairingKeySerParameter SecretKey=abe.keyGen(KeyPair.getPublic(), KeyPair.getPrivate(), accesspolicy, rhos);
	 Element recoverElementMessage =PairingFactory.getPairing(typeAParams).getGT().newOneElement().getImmutable();
	 
	 //密文属性
	 String[] attributes= {"11","33","44"};
	 System.out.print("密文属性：");
	 for(int k=0;k<attributes.length;k++) {
		  System.out.print(attributes[k]+" ");
	 }
	 System.out.print("\n");
	 //Encryption算法
	 GPSWCiphertextSerParameter Cipher=(GPSWCiphertextSerParameter) abe.encryption(KeyPair.getPublic(),attributes , elementMessage);
     System.out.println("密文："+Cipher.getEPrime().toString());
	
	
	 
	 //Dcryption算法
	 try {
		 recoverElementMessage=abe.decryption(KeyPair.getPublic(), SecretKey, attributes , Cipher).getImmutable();
	} catch (InvalidCipherTextException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	 if(elementMessage.isEqual(recoverElementMessage) ) {
		 System.out.println("解密："+PT.get(elementMessage));
		}
	
	
 }
 
	public static void main(String[] args){
		testGPSWABE();
	}
 
}
