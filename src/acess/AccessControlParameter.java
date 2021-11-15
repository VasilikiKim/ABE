package acess;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;


public class AccessControlParameter implements CipherParameters, java.io.Serializable {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	//The Access TreeCipherParameters,
    private final AccessTreeNode rootAccessTreeNode;//访问树根结点
    
    protected final int[][] accessPolicy;//访问策略（数组形式）
    //Rho map
    protected final String[] rhos;//属性集合

    /*生成访问控制参数*/
    /*包括访问树、访问策略和属性集合*/
    public AccessControlParameter(AccessTreeNode accessTreeNode, int[][] accessPolicy, String[] rhos) {
        this.rootAccessTreeNode = accessTreeNode;
        this.accessPolicy = accessPolicy;
        //复制属性集合
        this.rhos = new String[rhos.length];
        System.arraycopy(rhos, 0, this.rhos, 0, rhos.length);
    }

    /*获得属性集*/
    public String[] getRhos() {
        return this.rhos;
    }

    /*获得访问策略*/
    public int[][] getAccessPolicy() { return this.accessPolicy; }

    /*求出满足策略的最小属性集*/
    public String[] minSatisfiedAttributeSet(String[] attributes) throws UnsatisfiedAccessControlException {
        if (!this.rootAccessTreeNode.isAccessControlSatisfied(attributes)) {
            throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
        }
        boolean[] isRedundantAttribute = new boolean[attributes.length];
        int numOfMinAttributeSet = attributes.length;
        for (int i = 0; i < isRedundantAttribute.length; i++) {
            isRedundantAttribute[i] = true;
            numOfMinAttributeSet--;
            String[] minAttributeSet = new String[numOfMinAttributeSet];
            for (int j = 0, k = 0; j < attributes.length; j++) {
                if (!isRedundantAttribute[j]) {
                    minAttributeSet[k] = attributes[j];
                    k++;
                }
            }
            if (!this.rootAccessTreeNode.isAccessControlSatisfied(minAttributeSet)) {
                numOfMinAttributeSet++;
                isRedundantAttribute[i] = false;
            }
        }
        String[] minAttributeSet = new String[numOfMinAttributeSet];
        for (int j = 0, k = 0; j < attributes.length; j++) {
            if (!isRedundantAttribute[j]) {
                minAttributeSet[k] = attributes[j];
                k++;
            }
        }
        return minAttributeSet;
    }

    /*获得根结点*/
    public AccessTreeNode getRootAccessTreeNode() {
        return this.rootAccessTreeNode;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof AccessControlParameter) {
            AccessControlParameter that = (AccessControlParameter) anObject;
            //Compare rhos
            if (!Arrays.equals(this.rhos, that.getRhos())) {
                return false;
            }
            //Compare access policy
            if (this.accessPolicy.length != that.getAccessPolicy().length) {
                return false;
            }
            for (int i = 0; i < this.accessPolicy.length; i++) {
                if (!Arrays.equals(this.accessPolicy[i], that.getAccessPolicy()[i])) {
                    return false;
                }
            }
            //Compare AccessTreeNode
            return this.rootAccessTreeNode.equals(that.getRootAccessTreeNode());
        }
        return false;
    }
}
