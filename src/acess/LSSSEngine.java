package acess;

import acess.AccessControlParameter;
import acess.AccessTreeNode;
import acess.LSSSPolicyEngine;
import acess.LSSSPolicyParameter;

import acess.BinaryTreeNode;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;


public class LSSSEngine extends LSSSPolicyEngine {
    public static final String SCHEME_NAME = "linear secret-sharing scheme";

    private static LSSSEngine instance = new LSSSEngine();

    private LSSSEngine() {

    }

    public static LSSSEngine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public boolean isSupportThresholdGate() {
        return false;
    }

    public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) {
        //初始化访问树
        AccessTreeNode rootAccessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        //重建二叉树结点
        BinaryTreeNode rootBinaryTreeNode = BinaryTreeNode.ReconstructBinaryTreeNode(accessPolicy, rhos);

        //生成 lsss 矩阵
        Map<String, LinkedList<LinkedList<Integer>>> map = new LinkedHashMap<String, LinkedList<LinkedList<Integer>>>();
        int maxLen = 0;
        int rows = 0;
        //全局计数器c，初始为1
        int c = 1;
        LinkedList<Integer> vector = new LinkedList<Integer>();
        //由用长度为1的向量标记根结点开始
        vector.add(1);
        rootBinaryTreeNode.setVector(vector);

        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.AND) {
                //如果父结点是AND门，用向量v标记
                int size = p.getVector().size();
                LinkedList<Integer> pv = new LinkedList<Integer>();
                //在向量v后添0使得其长度为c
                if (size < c) {
                    pv.addAll(p.getVector());
                    for (int i = 0; i < c - size; i++) {
                        pv.add(0);
                    }
                } else {
                    pv.addAll(p.getVector());
                }
                //将它的孩子之一（右孩子）用向量 v|1标记
                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                lv.addAll(pv);
                lv.addLast(1);
                right.setVector(lv);
                queue.add(right);

                //将它的孩子之一（左孩子）用向量(0,...,0)|-1标记
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                for (int i = 0; i < c; i++) {
                    rv.add(0);
                }
                rv.addLast(-1);
                left.setVector(rv);
                queue.add(left);
                //c的值加1
                c += 1;
            } else if (p.getType() == BinaryTreeNode.NodeType.OR) {
                //如果父结点是由向量v标记的OR门，
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                //使用v标记其左孩子（c的值不变）
                lv.addAll(p.getVector());
                left.setVector(lv);
                queue.add(left);

                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                //使用v标记其右孩子（c的值不变）
                rv.addAll(p.getVector());
                right.setVector(rv);
                queue.add(right);
            } else {
                // 叶子结点
                rows += 1;
                int size = p.getVector().size();
                maxLen = size > maxLen ? size : maxLen;
                if (map.containsKey(p.getValue())) {
                    map.get(p.getValue()).add(p.getVector());
                } else {
                    LinkedList<LinkedList<Integer>> list = new LinkedList<LinkedList<Integer>>();
                    list.add(p.getVector());
                    map.put(p.getValue(), list);
                }
            }
        }

        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map
                .entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (LinkedList<Integer> aV : v) {
                int size = aV.size();
                if (size < maxLen) {
                    for (int j = 0; j < maxLen - size; j++) {
                        aV.add(0);
                    }
                }
            }
        }

        //构建lsss 矩阵
        int[][] lsssMatrix = new int[rows][];
        String[] rhosParameter = new String[rhos.length];
        int i = 0;
        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map.entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (LinkedList<Integer> aV : v) {
                rhosParameter[i] = entry.getKey();
                lsssMatrix[i] = new int[maxLen];
                for (int k = 0; k < maxLen; k++) {
                    lsssMatrix[i][k] = aV.get(k);
                }
                i += 1;
            }
        }
        return new LSSSPolicyParameter(rootAccessTreeNode, accessPolicy, lsssMatrix, rhosParameter);
    }
}