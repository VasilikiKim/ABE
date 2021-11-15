package acess;
import algorithm.Lagrange;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

public class AccessTreeEngine implements AccessControlEngine {

	public static String SCHEME_NAME = "general access tree";//方案名称

    private static AccessTreeEngine instance = new AccessTreeEngine();

    private AccessTreeEngine() {

    }

    public static AccessTreeEngine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public boolean isSupportThresholdGate() {
        return true;
    }

    /*生成访问控制参数：访问策略矩阵、访问树、属性集合*/
    /*输入：访问策略矩阵、属性域*/
   public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) {
        //init access tree
        AccessTreeNode accessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        return new AccessControlParameter(accessTreeNode, accessPolicy, rhos);
    }

    /*秘密分享算法*/
   public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) {
        Map<String, Element> sharedElementsMap = new HashMap<String, Element>();
        access_tree_node_secret_sharing(pairing, secret, accessControlParameter.getRootAccessTreeNode(), sharedElementsMap);
//        Object[] keySet = sharedElementsMap.keySet().toArray();
//        for (Object keys : keySet) {
//            System.out.println(keys + " : " + sharedElementsMap.get(keys));
//        }
       //System.out.println("oooops!");
        return sharedElementsMap;
    }
   

    /*由访问树生成秘密分享算法*/
    /*递归算法，最终分享结果保存在map<String,Element> sharingResult中*/
    /*输入：双线性对、秘密值、访问树结点、分享结果*/
   private void access_tree_node_secret_sharing(Pairing pairing, Element rootSecret, AccessTreeNode accessTreeNode, Map<String, Element> sharingResult) {
        if (accessTreeNode.isLeafNode()) {
            //是叶子结点，属性值与秘密值一起加入map
            sharingResult.put(accessTreeNode.getAttribute(), rootSecret.duplicate().getImmutable());
        } else {
            //non-leaf nodes, share secrets to child nodes
        	//不是叶子结点，向孩子节点分享秘密，构造多项式
        	//递归调用秘密分享算法
            Lagrange lagrangePolynomial = new Lagrange(pairing, accessTreeNode.getT() - 1, rootSecret);
            for (int i = 0; i < accessTreeNode.getN(); i++) {
                Element sharedSecret = lagrangePolynomial.evaluate(pairing.getZr().newElement(i + 1));
                access_tree_node_secret_sharing(pairing, sharedSecret, accessTreeNode.getChildNodeAt(i), sharingResult);
            }
        }
    }

    
    /*重建omega*/
    /*输入：双线性对、属性集合、访问控制参数*/
   public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter)
            throws UnsatisfiedAccessControlException {
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (String attribute : attributes) {
            if (collisionMap.containsKey(attribute)) {
                throw new UnsatisfiedAccessControlException("Invalid attribute set, containing identical attribute: " + attribute);
            } else {
                collisionMap.put(attribute, attribute);
            }
        }
        SatisfiedAccessTreeNode satisfiedAccessTreeNode = SatisfiedAccessTreeNode.GetSatisfiedAccessTreeNode(pairing, accessControlParameter.getRootAccessTreeNode());
        return SatisfiedAccessTreeNode.CalCoefficient(satisfiedAccessTreeNode, attributes);
    }

    
    private static class SatisfiedAccessTreeNode {
        private final Pairing pairing;//双线性对
        private final SatisfiedAccessTreeNode parentNode;//父结点
        private final SatisfiedAccessTreeNode[] childNodes;//孩子节点
        private final int index;//结点标号

        private final int t;//门限值
        private final int n;//子节点数
        private final boolean isLeafNode;//是否为叶子节点
        private final String attribute;//属性
        private int[] satisfiedIndex;//满足条件的结点标号
        private boolean isSatisfied;//子树是否满足条件

        /*构造函数*/
       static SatisfiedAccessTreeNode GetSatisfiedAccessTreeNode(Pairing pairing, AccessTreeNode rootAccessTreeNode) {
            return new SatisfiedAccessTreeNode(pairing, null, 0, rootAccessTreeNode);
        }

	
        /*计算拉格朗日系数*/
      static Map<String, Element> CalCoefficient(SatisfiedAccessTreeNode rootSatisfiedAccessTreeNode, String[] attributes) throws UnsatisfiedAccessControlException {
            if (!rootSatisfiedAccessTreeNode.isAccessControlSatisfied(attributes)) {
                throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
            } else {
                Map<String, Element> coefficientElementsMap = new HashMap<String, Element>();
                rootSatisfiedAccessTreeNode.calcCoefficients(coefficientElementsMap);
//                Object[] keySet = coefficientElementsMap.keySet().toArray();
//                for (Object keys : keySet) {
//                    System.out.println(keys + " : " + coefficientElementsMap.get(keys));
//                }
                return coefficientElementsMap;
            }
        }

        /*构造函数*/
        /*输入：双线性对、满足条件的子树父结点、结点标号、访问树根结点*/
       private SatisfiedAccessTreeNode(Pairing pairing, final SatisfiedAccessTreeNode parentSatisfiedAccessTreeNode, int index, final AccessTreeNode accessTreeNode) {
            this.pairing = pairing;
            this.parentNode = parentSatisfiedAccessTreeNode;
            this.index = index;
            if (accessTreeNode.isLeafNode()) {
                this.childNodes = null;
                this.t = 1;
                this.n = 1;
                this.attribute = accessTreeNode.getAttribute();
                this.isLeafNode = true;
            } else {
                this.t = accessTreeNode.getT();
                this.n = accessTreeNode.getN();
                this.isLeafNode = false;
                this.attribute = null;
                this.childNodes = new SatisfiedAccessTreeNode[this.n];
                for (int i = 0; i < this.childNodes.length; i++) {
                    this.childNodes[i] = new SatisfiedAccessTreeNode(pairing, this, i + 1, accessTreeNode.getChildNodeAt(i));
//                    System.out.println("Node: " + this.childNodes[i].label + " with parentNode: " + this.label);
                }
            }
        }

    
        
        
        
        
        /*判断属性集合是否满足访问控制策略*/
     private boolean isAccessControlSatisfied(final String[] attributes) {
            this.isSatisfied = false;
            if (!this.isLeafNode) {
                int[] tempIndex = new int[this.childNodes.length];
                int satisfiedChildNumber = 0;
                for (int i = 0; i < this.childNodes.length; i++) {
                    if (childNodes[i].isAccessControlSatisfied(attributes)) {
                        tempIndex[i] = i + 1;
                        satisfiedChildNumber++;
                    }
                }
                this.satisfiedIndex = new int[satisfiedChildNumber];
                for (int i = 0, j = 0; i < this.childNodes.length; i++) {
                    if (tempIndex[i] > 0) {
                        this.satisfiedIndex[j] = tempIndex[i];
                        j++;
                    }
                }
//                System.out.println("Node " + this.label + " has satisfied child nodes " + satisfiedChildNumber);
                this.isSatisfied = (satisfiedChildNumber >= t);
            } else {
                for (String attribute1 : attributes) {
                    if (this.attribute.equals(attribute1)) {
                        this.isSatisfied = true;
                    }
                }
            }
            return this.isSatisfied;
        }

      
        
        /*计算拉格朗日系数*/
       private void calcCoefficients(Map<String, Element> coefficientElementsMap) {
            if (!this.isLeafNode && this.isSatisfied) {
                for (SatisfiedAccessTreeNode childNode : this.childNodes) {
                    if (childNode.isSatisfied) {
                        childNode.calcCoefficients(coefficientElementsMap);
                    }
                }
            } else {
                if (!this.isSatisfied) {
                    return;
                }
                SatisfiedAccessTreeNode currentNode = this;
                Element coefficientElement =  pairing.getZr().newOneElement().getImmutable();
                while (currentNode.parentNode != null) {
                    int currentNodeIndex = currentNode.index;
                    currentNode = currentNode.parentNode;
                    coefficientElement = coefficientElement.mulZn(Lagrange.calCoef(pairing, currentNode.satisfiedIndex, currentNodeIndex)).getImmutable();
                }
                coefficientElementsMap.put(this.attribute, coefficientElement);
            }
        }
    }
    
    
   
    
	
}
