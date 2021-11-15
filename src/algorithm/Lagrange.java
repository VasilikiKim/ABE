package algorithm;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Lagrange {
	private final Pairing pairing;
    private final int degree;
    private final Element[] coef;

    
    /*构造拉格朗日多项式*/
    /*输入：双线性配对、多项式指数、零点值*/
    public Lagrange(Pairing pairing, int degree, Element zeroValue) {
        this.pairing = pairing;
        this.degree = degree;
        this.coef = new Element[this.degree + 1];
        this.coef[0] = zeroValue.duplicate().getImmutable();
        for (int i = 1; i < coef.length; i++) {
            this.coef[i] = this.pairing.getZr().newRandomElement()
                    .getImmutable();
        }
    }

   /*计算x的多项式值Poly(x)*/
    public Element evaluate(Element x) {
        Element result = pairing.getZr().newZeroElement().getImmutable();
        Element temp = pairing.getZr().newOneElement().getImmutable();

        for (int i = 0; i < this.degree + 1; i++) {
            for (int j = 0; j < i; j++) {
                temp = temp.mul(x).getImmutable();
            }
            temp = temp.mul(coef[i]).getImmutable();
            result = result.add(temp).getImmutable();
            temp = pairing.getZr().newOneElement().getImmutable();
        }
        return result;
    }

   
    /*计算拉格朗日系数*/
    /*输入：索引集合S和索引i*/
    /*输出：\dalta_(i, S)(0)*/
    public static Element calCoef(Pairing pairing, int[] set, int index) {
        Element[] elementSet = new Element[set.length];
        for (int i = 0; i < set.length; i++) {
            elementSet[i] = pairing.getZr().newElement(set[i]).getImmutable();
        }
        Element elementIndex = pairing.getZr().newElement(index).getImmutable();
        Element result = pairing.getZr().newOneElement().getImmutable();

        for (int i = 0; i < set.length; i++) {
            if (set[i] == index) {
                continue;
            }
            Element member = pairing.getZr().newZeroElement()
                    .sub(elementSet[i]).getImmutable();
            Element denominator = elementIndex.sub(elementSet[i])
                    .getImmutable();
            result = result.mul(member).mul(denominator.invert());
        }
        return result;
    }
}
