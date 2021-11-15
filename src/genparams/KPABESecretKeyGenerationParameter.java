package genparams;

import acess.AccessControlEngine;
import genparams.PairingKeyGenerationParameter;
import serparams.PairingKeySerParameter;

public class KPABESecretKeyGenerationParameter  extends PairingKeyGenerationParameter{
	 private AccessControlEngine accessControlEngine;
	    private int[][] accessPolicy;
	    private String[] rhos;

	    public KPABESecretKeyGenerationParameter(
	            AccessControlEngine accessControlEngines, PairingKeySerParameter publicKeyParameter,
	            PairingKeySerParameter masterSecretKeyParameter, int[][] accessPolicy, String[] rhos) {
	        super(publicKeyParameter, masterSecretKeyParameter);
	        this.accessControlEngine = accessControlEngines;
	        this.accessPolicy = accessPolicy;
	        this.rhos = rhos;
	    }

	    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }

	    public int[][] getAccessPolicy() { return this.accessPolicy; }

	    public String[] getRhos() { return this.rhos; }
}
