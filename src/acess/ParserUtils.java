package acess;

import java.util.ArrayList;
import java.util.LinkedList;

public class ParserUtils {
	private static char SPACE = ' ';

	/*对输入的访问控制策略格式修改*/
    private static String StringPolicyFormat(String policy) {
        policy = policy.trim();
        policy = policy.replaceAll("\\(", "(" + ParserUtils.SPACE);
        policy = policy.replaceAll("\\)", ParserUtils.SPACE + ")");
        return policy;
    }

    /*生成访问策略矩阵*/
    /*输入：策略字符串*/
    /*输出：策略矩阵*/
    public static int[][] GenerateAccessPolicy(String policy) throws PolicySyntaxException {
        
    	String formattedPolicy = StringPolicyFormat(policy);//格式转换
    	//解析策略
        BinaryTreeNode rootBinaryTreeNode = new PolicyParser().parse(formattedPolicy);
        BinaryTreeNode.updateParentPointer(rootBinaryTreeNode);

        LinkedList<int[]> accessPolicyLinkedList = new LinkedList<int[]>();
        //convert to int[][] accessPolicy
        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        int nextNodeLabel = 0;
        int nextLeafNodeLabel = 1;
        int labelLeft = 0;
        int labelRight = 0;
        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.LEAF) {
                continue;
            } else {
                if (p.getLeft().getType() == BinaryTreeNode.NodeType.LEAF) {
                    labelLeft = -1 * nextLeafNodeLabel;
                    nextLeafNodeLabel++;
                } else {
                    labelLeft = ++nextNodeLabel;
                }
                if (p.getRight().getType() == BinaryTreeNode.NodeType.LEAF) {
                    labelRight = -1 * nextLeafNodeLabel;
                    nextLeafNodeLabel++;
                } else {
                    labelRight = ++nextNodeLabel;
                }
                queue.add(p.getLeft());
                queue.add(p.getRight());
                if (p.getType() == BinaryTreeNode.NodeType.AND) {
                    accessPolicyLinkedList.add(new int[] {2, 2, labelLeft, labelRight});
                } else {
                    accessPolicyLinkedList.add(new int[] {2, 1, labelLeft, labelRight});
                }
            }
        }
        if (accessPolicyLinkedList.size() == 0) {
            int[][] accessPolicy = new int[1][];
            accessPolicy[0] = new int[] {1, 1, -1};
            return accessPolicy;
        }
        int[][] accessPolicy = new int[accessPolicyLinkedList.size()][];
        for (int i = 0; i < accessPolicyLinkedList.size(); i++) {
            accessPolicy[i] = accessPolicyLinkedList.get(i);
        }
        return accessPolicy;
    }

    /*生成属性集合*/
    /*输入：策略字符串*/ 
    /*输出：属性集合*/
    public static String[] GenerateRhos(String policy) throws PolicySyntaxException {
        String formattedPolicy = StringPolicyFormat(policy);
        BinaryTreeNode rootBinaryTreeNode = new PolicyParser().parse(formattedPolicy);
        BinaryTreeNode.updateParentPointer(rootBinaryTreeNode);

        ArrayList<String> rhosArrayList = new ArrayList<String>();
        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);
        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.LEAF) {
                rhosArrayList.add(p.getValue());
            } else {
                queue.add(p.getLeft());
                queue.add(p.getRight());
            }
        }
        String[] rhos = new String[rhosArrayList.size()];
        for (int i = 0; i < rhos.length; i++) {
            rhos[i] = rhosArrayList.get(i);
        }
        return rhos;
    }
}
