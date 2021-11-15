package acess;
import java.util.LinkedList;

public class BinaryTreeNode {
	 public enum NodeType {//结点类型
	        AND, OR, LEAF,
	    }

	    private NodeType type;
	    private String value;	//叶子结点值，即属性
	    private BinaryTreeNode parent;
	    private BinaryTreeNode left;
	    private BinaryTreeNode right;
	    private LinkedList<Integer> vector;

	    public LinkedList<Integer> getVector() {
	        return vector;
	    }
	    public void setVector(LinkedList<Integer> vector) {
	        this.vector = vector;
	    }
	    public BinaryTreeNode getParent() {
	        return parent;
	    }
	    public void setParent(BinaryTreeNode parent) {
	        this.parent = parent;
	    }
	    public String getValue() {
	        return value;
	    }
	    public void setValue(String value) {
	        this.value = value;
	    }
	    public NodeType getType() {
	        return type;
	    }
	    public void setType(NodeType type) {
	        this.type = type;
	    }
	    public BinaryTreeNode getLeft() {
	        return left;
	    }
	    public void setLeft(BinaryTreeNode left) {
	        this.left = left;
	    }
	    public BinaryTreeNode getRight() {
	        return right;
	    }
	    public void setRight(BinaryTreeNode right) {
	        this.right = right;
	    }

	    //二叉树先序遍历
	    public static void preOrderTraversal(BinaryTreeNode root){
	        if(root == null){
	            return;
	        }
	        System.out.println(root);
	        preOrderTraversal(root.getLeft());
	        preOrderTraversal(root.getRight());
	    }

	    //后序遍历
	    public static void postOrderTraversal(BinaryTreeNode root){
	        if(root == null){
	            return;
	        }
	        postOrderTraversal(root.getLeft());
	        System.out.println(root);
	        postOrderTraversal(root.getRight());
	    }

	    //中序遍历
	    public static void inOrderTraversal(BinaryTreeNode root){
	        if(root == null){
	            return;
	        }
	        inOrderTraversal(root.getLeft());
	        inOrderTraversal(root.getRight());
	        System.out.println(root);
	    }

	    //更新父结点
	    public static void updateParentPointer(BinaryTreeNode root){
	        BinaryTreeNode p = root;
	        BinaryTreeNode left = root.getLeft();
	        BinaryTreeNode right = root.getRight();
	        if(left != null){
	            left.setParent(p);
	            updateParentPointer(left);
	        }
	        if(right != null){
	            right.setParent(p);
	            updateParentPointer(right);
	        }
	    }

	    /*重建二叉树*/
	    /*输入：访问策略矩阵、属性域*/
	    public static BinaryTreeNode ReconstructBinaryTreeNode(int[][] accessPolicy, String[] rhos) {
	        BinaryTreeNode[] binaryNonleafTreeNodes = new BinaryTreeNode[accessPolicy.length];
	        
	        /****************使用访问矩阵构造二叉树*************/
	        /**************************************************/
	        for (int i = 0; i < accessPolicy.length; i++) {
	            binaryNonleafTreeNodes[i] = new BinaryTreeNode();
	            if (accessPolicy[i][0] == 2 && accessPolicy[i][1] == 2) {
	                //AND GATE
	                binaryNonleafTreeNodes[i].setType(NodeType.AND);
	            } else if (accessPolicy[i][0] == 2 && accessPolicy[i][1] == 1) {
	                //OR GATE
	                binaryNonleafTreeNodes[i].setType(NodeType.OR);
	            }
	        }
	        /**************************************************/
	        
	        
	        for (int i = 0; i < accessPolicy.length; i++) {
	            //链接左孩子
	            if (accessPolicy[i][2] > 0) {//是非叶子结点
	                //link non-leaf nodes
	                binaryNonleafTreeNodes[i].setLeft(binaryNonleafTreeNodes[accessPolicy[i][2]]);
	                binaryNonleafTreeNodes[accessPolicy[i][2]].setParent(binaryNonleafTreeNodes[i]);
	            } else {
	                //link leaf node//链接叶子结点
	                BinaryTreeNode leafNode = new BinaryTreeNode();
	                leafNode.setType(NodeType.LEAF);
	                leafNode.setValue(rhos[-1 * accessPolicy[i][2] - 1]);
	                binaryNonleafTreeNodes[i].setLeft(leafNode);
	                leafNode.setParent(binaryNonleafTreeNodes[i]);
	            }
	            //link right node
	            if (accessPolicy[i][3] > 0) {
	                //link non-leaf nodes
	                binaryNonleafTreeNodes[i].setRight(binaryNonleafTreeNodes[accessPolicy[i][3]]);
	                binaryNonleafTreeNodes[accessPolicy[i][3]].setParent(binaryNonleafTreeNodes[i]);
	            } else {
	                //link leaf node
	                BinaryTreeNode leafNode = new BinaryTreeNode();
	                leafNode.setType(NodeType.LEAF);
	                leafNode.setValue(rhos[-1 * accessPolicy[i][3] - 1]);
	                binaryNonleafTreeNodes[i].setRight(leafNode);
	                leafNode.setParent(binaryNonleafTreeNodes[i]);
	            }
	        }
	        return binaryNonleafTreeNodes[0];
	    }

	    @Override
	    public String toString(){
	        return this.type == NodeType.LEAF ?
	                this.type + ":" + this.value :
	                this.type.toString();
	    }
}
