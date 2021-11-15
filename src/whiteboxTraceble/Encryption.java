package whiteboxTraceble;

import acess.ParserUtils;
import acess.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import serparams.PairingKeySerPair;
import utils.PairingUtils;
import utils.PairingUtils.PairingGroupType;

public class Encryption {
	
	protected static int[][] accessPolicy;
	
	protected static Element elementMessage;
	
	protected static String Message;
	
	protected static CiphertextSerParameter cipher;
	
	protected static String[] rhos;
	
	public static String encryText(String message, String accessPolicyMessage) {
		
		WhiteBoxEngine abe = new WhiteBoxEngine();
		int rBits = 160; //群的阶
		int qBits = 512; // zq的阶。
		TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits); //指定椭圆曲线的种类 typeA
		PairingParameters typeAParams = pg.generate();
		String[] attributeUniverse= {"A","B","C","D","E"};
		int maxNumAttributes=5;
		PairingKeySerPair KeyPair = abe.setup(typeAParams, maxNumAttributes, attributeUniverse);
		
		try {
			 accessPolicy=ParserUtils.GenerateAccessPolicy(accessPolicyMessage);
		} catch (PolicySyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		rhos=new String[accessPolicy.length];
		 try {
			rhos=ParserUtils.GenerateRhos(accessPolicyMessage);
		} catch (PolicySyntaxException e) {
			// TODO Auto-generated catch block
			System.out.println("here");
			e.printStackTrace();
		}
		 
		 elementMessage=PairingUtils.MapStringToGroup(PairingFactory.getPairing(typeAParams), message, PairingGroupType.GT).getImmutable();
	
		 CiphertextSerParameter cipher = (CiphertextSerParameter) abe.encryption(KeyPair.getPublic(), accessPolicy, rhos, elementMessage);
		 return cipher.getC().toString();
	}
}
