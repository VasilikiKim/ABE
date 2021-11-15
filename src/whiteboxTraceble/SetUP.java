package whiteboxTraceble;

import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import serparams.PairingKeySerPair;

public class SetUP {
	
	protected static WhiteBoxEngine abe = new WhiteBoxEngine();
	protected static int rBits = 160; //群的阶
	protected static int qBits = 512; // zq的阶。
	protected static TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits); //指定椭圆曲线的种类 typeA
	protected static PairingParameters typeAParams = pg.generate();
//	protected static String[] attributeUniverse=  {"A","B","C","D","E","F","G","H","I","J","K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"};
//	protected static String[] attributeUniverse= {"A","B","C","D","E"};
//	protected static String[] attributeUniverse= {"A","B","C","D","E","F","G","H","I","J"};
	protected static String[] attributeUniverse={"A","B","C","D","E","F","G","H","I","J","K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d"};
//	protected static String[] attributeUniverse = {"A","B","C","D","E","F","G","H","I","J","K", "L", "M", "N", "O", "P", "Q", "R", "S", "T"};
	protected static int maxNumAttributes=30;
	protected static PairingKeySerPair keyPair = abe.setup(typeAParams, maxNumAttributes, attributeUniverse);
}
