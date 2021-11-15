package acess;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;


public class AccessTreeNode implements java.io.Serializable {
	
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private static int numberOfLeafNodes = 0;//叶子节点数量
    private final AccessTreeNode[] childNodes;//孩子节点数组
    private final int t;//阈值
    private final int label;//标号
    private final String attribute;//属性
    private final boolean isLeafNode;//是否为叶子节点
    
    /*生成访问树*/
    /*输入：访问策略、属性集合*/
    /*输出：访问树根结点*/
    public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) {
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (String rho : rhos) {//输入属性集合，如果属性集合中有相同两个属性，则出错
            if (collisionMap.containsKey(rho)) {
                throw new InvalidParameterException("Invalid access policy, rhos containing identical string: " + rho);
            } else {
                collisionMap.put(rho, rho);
            }
        }
        numberOfLeafNodes = 0;
        AccessTreeNode rootAccessTreeNode = new AccessTreeNode(accessPolicy, 0, rhos);//构造根结点
        if (numberOfLeafNodes != rhos.length) {//叶子节点数和属性数匹配
            throw new InvalidParameterException("Invalid access policy, number of leaf nodes " + numberOfLeafNodes
                    + " does not match number of rhos " + rhos.length);
        }
        return rootAccessTreeNode;
    }

  
    /*构造叶子节点*/
    /*输入：标号、属性*/
    private AccessTreeNode(final int i, final String rho) {
        this.childNodes = null;
        this.t = 0;
        this.label = i;
        this.isLeafNode = true;
        this.attribute = rho;
    }

    /*构造访问树节点*/
    /*输入：访问策略、节点标号、属性集合*/
    private AccessTreeNode(final int[][] accessPolicy, final int i, final String[] rhos) {
        
    	int[] accessPolicyNode = accessPolicy[i];//节点i
        if (accessPolicyNode[0] < accessPolicyNode[1]) {//判断：应满足子节点数>=门限值
            throw new InvalidParameterException("Invalid access policy, n < t in the threahold gate " + i);
        }
        
        this.childNodes = new AccessTreeNode[accessPolicyNode[0]];//创建孩子数组，大小为accessPolicyNode[0]
        this.t = accessPolicyNode[1];//门限值
        this.label = i;//节点标号
        this.attribute = null;//属性置空
        this.isLeafNode = false;//不是叶子节点
        
        int k = 0;
        for (int j = 2; j < accessPolicyNode.length; j++) {//遍历孩子节点
            if (accessPolicyNode[j] > 0) {//标号为正，则为非叶子节点
                this.childNodes[k] = new AccessTreeNode(accessPolicy, accessPolicyNode[j], rhos);//构造子节点
            } else if (accessPolicyNode[j] < 0) {//标号为负，为叶子节点
                numberOfLeafNodes++;//叶子数量+1
                this.childNodes[k] = new AccessTreeNode(accessPolicyNode[j], rhos[-accessPolicyNode[j] - 1]);//构造叶子节点
            } else {
                throw new InvalidParameterException("Invalid access policy, containing access node with index 0");
            }
            k++;
        }
    }

    /*判断属性集合是否满足访问策略*/
    /*输入：属性集合*/
    /*输出：布尔变量*/
    boolean isAccessControlSatisfied(final String[] attributes) {
        if (!this.isLeafNode) {//不是叶子节点
            int satisfiedChildNumber = 0;
            for (AccessTreeNode childNode : this.childNodes) {//遍历其孩子节点
                if (childNode.isAccessControlSatisfied(attributes)) {
                    satisfiedChildNumber++;
                }
            }
            return (satisfiedChildNumber >= t);//与门限值比较
        } else {//是叶子节点，判断是否有相同属性
            for (String eachAttribute : attributes) {
                if (this.attribute.equals(eachAttribute)) {
                    return true;
                }
            }
            return false;
        }
    }

    /*得到门限值*/
    public int getT() {
        return this.t;
    }

    /*得到子节点数*/
    public int getN() {
        return this.childNodes.length;
    }

    /*按索引得到目标孩子节点*/
    public AccessTreeNode getChildNodeAt(int index) {
        return this.childNodes[index];
    }

    /*判断是否是叶子节点*/
    public boolean isLeafNode() {
        return this.isLeafNode;
    }

    /*获得节点属性*/
    public String getAttribute() {
        return this.attribute;
    }

    /*获得节点标号*/
    public int getLabel() {
        return this.label;
    }

    /*判断两节点是否相等*/
    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof AccessTreeNode) {
            AccessTreeNode that = (AccessTreeNode) anOjbect;
            //Compare t;
            if (this.t != that.getT()) {
                return false;
            }
            //Compare label
            if (this.label != that.getLabel()) {
                return false;
            }
            //Compare leafnode
            if (this.isLeafNode) {
                //Compare attribute
                if (!this.attribute.equals(that.attribute)) {
                    return false;
                }
                return this.isLeafNode == that.isLeafNode;
            } else {
                //Compare nonleaf nodes
                if (this.childNodes.length != that.childNodes.length) {
                    return false;
                }
                for (int i = 0; i < this.childNodes.length; i++) {
                    //Compare child nodes
                    if (!this.childNodes[i].equals(that.getChildNodeAt(i))) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }
}
