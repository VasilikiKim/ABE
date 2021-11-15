package acess;
import java.util.Arrays;

	
public class LSSSPolicyParameter extends AccessControlParameter {
	    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
		//The LSSS matrix
	    private int[][] lsssMatrix;
	    //number of rows
	    private int row;
	    //number of columns
	    private int column;

	    public LSSSPolicyParameter(AccessTreeNode rootAccessTreeNode, int[][] accessPolicy, int[][] lsssMatrix, String[] rhos) {
	        super(rootAccessTreeNode, accessPolicy, rhos);
	        this.row = lsssMatrix.length;
	        this.column = lsssMatrix[0].length;
	        this.lsssMatrix = new int[row][column];
	        //Copy LSSS Matrix
	        for (int i=0; i<this.row; i++) {
	            System.arraycopy(lsssMatrix[i], 0, this.lsssMatrix[i], 0, column);
	        }
	    }

	    int getRow() {
	        return this.row;
	    }

	    int getColumn() { return this.column; }

	    int[][] getLSSSMatrix(){
	        return this.lsssMatrix;
	    }

	    public String[] getRhos() {
	        return this.rhos;
	    }
	    
	    
       //将LSSS矩阵和属性集合转换成字符串形式
	    @Override
	    public String toString(){
	        StringBuilder buffer = new StringBuilder("LSSS访问结构(M,ρ):\n");
	        for(int i=0; i<row; i++){
	            buffer.append(" |");// buffer.append(i).append(" |");
	            for(int j=0; j<column; j++){
	            	
	            	if(lsssMatrix[i][j]<0) {
	            		buffer.append(" ");
	            	}
	            	else {
	            		buffer.append("  ");
	            	}
	                buffer.append(lsssMatrix[i][j]);
	                
	            }
	            buffer.append("| ").append(rhos[i]);
	            buffer.append("\n");
	        }
	        return buffer.toString();
	    }

	    @Override
	    public boolean equals(Object anObject) {
	        if (this == anObject) {
	            return true;
	        }
	        if (anObject instanceof LSSSPolicyParameter) {
	            LSSSPolicyParameter that = (LSSSPolicyParameter) anObject;
	            //Compare row
	            if (this.row != that.getRow()) {
	                return false;
	            }
	            //Compare column
	            if (this.column != that.getColumn()) {
	                return false;
	            }
	            //Compare lsss matrix
	            if (this.lsssMatrix.length != that.getLSSSMatrix().length) {
	                return false;
	            }
	            for (int i = 0; i < this.lsssMatrix.length; i++) {
	                if (!Arrays.equals(this.lsssMatrix[i], that.lsssMatrix[i])) {
	                    return false;
	                }
	            }
	            return true;
	        }
	        return false;
	    }
	}

