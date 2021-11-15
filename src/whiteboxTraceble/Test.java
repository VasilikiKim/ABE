package whiteboxTraceble;

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

public class Test {
	
	private static void testWBT() {
		WhiteBoxEngine engine = new WhiteBoxEngine();
		
		int rBits = 160;
		int qBits = 512;
		
		System.out.println("加密机制: "+engine.getEngineName());
		System.out.print("\n");
		
		TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
		PairingParameters typeAParams = pg.generate();
	
		String[] attributeUniverse = {"A","B","C","D","E","F"};
		
		int maxNum = 20;
		
		PairingKeySerPair KeyPair = engine.setup(typeAParams, maxNum, attributeUniverse);
		
		//String AccessPolicy = "(A AND B AND C AND D AND E AND F AND G AND H AND I AND J AND K AND L AND M AND N AND O AND P AND Q AND R AND S AND T)";
		String AccessPolicy = "(A and (B or C) and (D or E))";
		System.out.println("访问策略："+AccessPolicy);
		
		int[][] accessPolicyMatrix = null;
		try {
			accessPolicyMatrix = ParserUtils.GenerateAccessPolicy(AccessPolicy);
		} catch (PolicySyntaxException e) {
			e.printStackTrace();
		}
		
		String[] rhos = new String[accessPolicyMatrix.length];
		try {
			rhos = ParserUtils.GenerateRhos(AccessPolicy);
		} catch(PolicySyntaxException e) {
			e.printStackTrace();
		}
		
		String message = "Attribute-based encryption";
		Element elementMessage = PairingUtils.MapStringToGroup(PairingFactory.getPairing(typeAParams), message, PairingGroupType.GT);
		//System.out.println(elementMessage.toString());
		System.out.println("明文 ："+ message);
		System.out.print("\n");
		CiphertextSerParameter Cipher = engine.encryption(KeyPair.getPublic(), accessPolicyMatrix, rhos, elementMessage);
		System.out.println("密文 :" + Cipher.getC().toString());
		System.out.print("\n ");
		System.out.print("用户属性：");
		String[] attributes = {"A","B","E"};
		
		for(String str:attributes) {
			System.out.print(str+" ");
		}
		System.out.print("\n ");
		
		PairingKeySerParameter SecretKey = engine.keyGen(KeyPair.getPublic(), KeyPair.getPrivate(), attributes);
		Element recoverElementMessage = PairingFactory.getPairing(typeAParams).getGT().newOneElement().getImmutable();
		
		try {
			recoverElementMessage = engine.decryption(KeyPair.getPublic(), SecretKey, accessPolicyMatrix, rhos, Cipher);
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
		
		//System.out.println(recoverElementMessage.toString());
		System.out.println("解密 ："+ message);
		
	}
	
	public static void main(String[] args) {
		//long start = System.currentTimeMillis();
		testWBT();
		//long end = System.currentTimeMillis();
		//System.out.println(end - start);
	}
}