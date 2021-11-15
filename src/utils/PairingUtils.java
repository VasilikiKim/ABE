package utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class PairingUtils {
    public static final String PATH_a_160_512 = "params/a_160_512.properties";
//    public static final String PATH_a_320_512 = "params/a_320_512.properties";
//    public static final String PATH_a1_2_256 = "params/a1_2_256.properties";
//    public static final String PATH_a1_3_256 = "params/a1_3_256.properties";
//    public static final String PATH_a1_2_512 = "params/a1_2_512.properties";
    public static final String PATH_a1_3_512 = "params/a1_3_512.properties";
    public static final String PATH_f_160 = "params/f_160.properties";

    public enum PairingGroupType {
        Zr, G1, G2, GT,
    }

//    public static final PairingParameters DEFAULT_TYPE_A_160_512_PAIRING_PARAMETER = PairingFactory.getPairingParameters()

//    /**
//     * Generate type A parameter for further used in paiaring-based cryptography.
//     * @param rBitLength Bit length for the group Z_r
//     * @param qBitLength Bit length for the group G and G_T
//     * @return Type A pairing parameters
//     */
//    public static PropertiesParameters GenerateTypeAParameters(int rBitLength, int qBitLength) {
//        PropertiesParameters parameters;
//        Pairing pairing;
//        Element g;
//        // Generate curve parameters
//        while (true) {
//            parameters = generate_type_a_curve_params(rBitLength, qBitLength);
//            pairing = PairingFactory.getPairing(parameters);
//            g = pairing.getG1().newRandomElement().getImmutable();
//            if (!pairing.pairing(g, g).isOne()) { break; }
//        }
//        return parameters;
//    }

//    public static PropertiesParameters GenerateTypeA1Parameters(int qBitLength) {
//        PropertiesParameters parameters;
//        Pairing pairing;
//        Element generator;
//        Element g;
//
//        // Generate curve parameters
//        while (true) {
//            parameters = generate_type_a1_curve_params(qBitLength);
//            pairing = PairingFactory.getPairing(parameters);
//            generator = pairing.getG1().newRandomElement().getImmutable();
//            g = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
//            if (!pairing.pairing(g, g).isOne()) { break; }
//        }
//        return parameters;
//    }

//    private static PropertiesParameters generate_type_a_curve_params(int rBitLength, int qBitLength) {
//        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(rBitLength, qBitLength);
//        return (PropertiesParameters) parametersGenerator.generate();
//    }

//    private static PropertiesParameters generate_type_a1_curve_params(int qBitLength) {
//        PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(3, qBitLength);
//        return (PropertiesParameters) parametersGenerator.generate();
//    }

    /**
     * 用于映射的标准抵抗冲突哈希函数，使用SHA-256.
     * 输入：被哈希的字节数组
     * 输出：哈希结果
     */
    private static byte[] hash(byte[] message) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            //Impossible to get this exception
            e.printStackTrace();
        }
        assert (md != null);
        md.update(message);
        return md.digest();
    }

    /**
     * 将字节数组映射为群中一个元素
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return Element
     */
    public static Element MapByteArrayToGroup(Pairing pairing, byte[] message, PairingGroupType pairingGroupType) {
        byte[] shaResult = hash(message);
        switch (pairingGroupType) {
            case Zr: return pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case G1: return pairing.getG1().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case G2: return pairing.getG2().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case GT: return pairing.getGT().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            default: throw new RuntimeException("无效群类型！");
        }
    }

    /**
     * 将字符串映射为群中一元素
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return
     */ 
    public static Element MapStringToGroup(Pairing pairing, String message, PairingGroupType pairingGroupType) {
        return PairingUtils.MapByteArrayToGroup(pairing, message.getBytes(), pairingGroupType);
    }

    /**
     * 将字节数组映射为群Zr前半部分的一个元素
     * @param pairing
     * @param message
     * @return
     */
    public static Element MapByteArrayToFirstHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(message);
        byte[] hashZr = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
        hashZr[0] &= 0xEF;
        return pairing.getZr().newElementFromBytes(hashZr).getImmutable();
    }

    /**
     * 将字节数组映射为群Zr后半部分的一个元素
     * @param pairing
     * @param message
     * @return
     */
    public static Element MapByteArrayToSecondHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(message);
        byte[] hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
        hash[0] |= 0x80;
        return pairing.getZr().newElementFromBytes(hash).getImmutable();
    }

    /**
     * 将字符串数组映射为群中元素数组
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return
     */
    public static Element[] MapStringArrayToGroup(Pairing pairing, String[] message, PairingGroupType pairingGroupType){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            if (message[i] == null) {
                continue;
            }
            elements[i] = PairingUtils.MapByteArrayToGroup(pairing, message[i].getBytes(), pairingGroupType);
        }
        return elements;
    }

    /**
     * 将字符串数组映射为群Zr前半部分的元素数组
     * @param pairing
     * @param message
     * @return
     */
    public static Element[] MapStringArrayToFirstHalfZr(Pairing pairing, String[] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = PairingUtils.MapByteArrayToFirstHalfZr(pairing, message[i].getBytes());
        }
        return elements;
    }

    /**
     * 将元素数组转为字符串数组形式
     * @param message
     * @return
     */
    public static String[] MapElementArrayToStringArray(Element[] message) {
        String[] strings = new String[message.length];
        for (int i = 0; i < message.length; i++) {
            strings[i] = message[i].toString();
        }
        return strings;
    }

    /**
     * 将元素转为字符串形式
     * @param message
     * @return
     */
    public static String MapElementToString(Element message) {
        String string = new String();
         string=message.toString();
      
        return string;
    }
    
    
    /**
     * 判断两个元素是否相等
     * @param thisElement
     * @param thatElement
     * @return
     */
    public static boolean isEqualElement(final Element thisElement, final Element thatElement) {
        if (thisElement == null && thatElement != null) {
            return false;
        }
        if (thisElement != null && thatElement == null) {
            return false;
        }
        if (thisElement == thatElement) {
            return true;
        }
        String stringThisElement = new String(Hex.encode(thisElement.toBytes()));
        String stringThatElement = new String(Hex.encode(thatElement.toBytes()));
        return (stringThisElement.equals(stringThatElement));
    }

    /**
     * 判断两个元素数组是否相等
     * @param thisElementArray
     * @param thatElementArray
     * @return
     */
    public static boolean isEqualElementArray(final Element[] thisElementArray, final Element[] thatElementArray) {
        if (thisElementArray == thatElementArray) {
            return true;
        }
        if (thisElementArray.length != thatElementArray.length) {
            return false;
        }
        for (int i=0; i<thisElementArray.length; i++){
            if (!(PairingUtils.isEqualElement(thisElementArray[i], thatElementArray[i]))){
                return false;
            }
        }
        return true;
    }

    /**
     * 判断两个字节数组是否相等
     * @param thisByteArrays
     * @param thatByteArrays
     * @return
     */
    public static boolean isEqualByteArrays(final byte[][] thisByteArrays, final byte[][] thatByteArrays) {
        if (thisByteArrays == thatByteArrays) {
            return true;
        }
        if (thisByteArrays.length != thatByteArrays.length) {
            return false;
        }
        for (int i=0; i<thisByteArrays.length; i++){
            if (!(Arrays.equals(thisByteArrays[i], thatByteArrays[i]))){
                return false;
            }
        }
        return true;
    }

    /**
     * 判断两个字节数组的映射是否相等
     * @param thisMap
     * @param thatMap
     * @return
     */
    public static boolean isEqualByteArrayMaps(final Map<String, byte[]> thisMap, final Map<String, byte[]> thatMap) {
        if (thisMap == thatMap) {
            return true;
        }
        for (String thisString : thisMap.keySet()) {
            if (!Arrays.equals(thisMap.get(thisString), thatMap.get(thisString))) {
                return false;
            }
        }
        for (String thatString : thatMap.keySet()) {
            if (!Arrays.equals(thisMap.get(thatString), thatMap.get(thatString))) {
                return false;
            }
        }
        return true;
    }

    /**
     * 获得元素数组的字节数组
     * @param elementArray
     * @return
     */
    public static byte[][] GetElementArrayBytes(Element[] elementArray) {
        byte[][] byteArrays = new byte[elementArray.length][];
        for (int i = 0; i < byteArrays.length; i++) {
            if (elementArray[i] == null) {
                byteArrays[i] = null;
                continue;
            }
            byteArrays[i] = elementArray[i].toBytes();
        }
        return byteArrays;
    }

    /**
     * 由字节数组得到元素数组
     * @param pairing
     * @param byteArrays
     * @param groupType
     * @return
     */
    public static Element[] GetElementArrayFromBytes(Pairing pairing, byte[][] byteArrays, PairingGroupType groupType) {
        Element[] elementArray = new Element[byteArrays.length];
        for (int i = 0; i < elementArray.length; i++) {
            if (byteArrays[i] == null) {
                elementArray[i] = null;
                continue;
            }
            switch (groupType) {
                case Zr: elementArray[i] = pairing.getZr().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case G1: elementArray[i] = pairing.getG1().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case G2: elementArray[i] = pairing.getG2().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case GT: elementArray[i] = pairing.getGT().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                default:
                    throw new RuntimeException("Invalid pairing group type.");
            }
        }
        return elementArray;
    }

    /**
     * 去掉字符串数组中的重复字符串
     * @param orginalArray
     * @return
     */
    public static String[] removeDuplicates(String[] orginalArray) {
        Set<String> stringSet = new HashSet<String>();
        Collections.addAll(stringSet, orginalArray);
        return stringSet.toArray(new String[1]);
    }

    /**
     * 去掉int数组中的重复值
     * @param originalArray
     * @return
     */
    public static int[] removeDuplicates(int[] originalArray) {
        Set<Integer> intSet = new HashSet<Integer>();
        for (int i : originalArray) {
            intSet.add(i);
        }
        int[] resultSet = new int[intSet.size()];
        int label = 0;
        for (Integer setInteger : intSet) {
            resultSet[label] = setInteger;
            label++;
        }
        return resultSet;
    }

    /**
     * 将密文转换为字节数组
     * @param cipherParameters
     * @return
     * @throws IOException
     */
    public static byte[] SerCipherParameter(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(cipherParameters);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();
        return byteArray;
    }

    /**
     * 读取密文
     * @param byteArrays
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static CipherParameters deserCipherParameters(byte[] byteArrays) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrays);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        CipherParameters cipherParameters = (CipherParameters)objectInputStream.readObject();
        objectInputStream.close();
        byteArrayInputStream.close();
        return cipherParameters;
    }

    /**
     * 未识别出的密文实例
     * @param schemeName
     * @param parameters
     * @param className
     */
    public static void NotVerifyCipherParameterInstance(String schemeName, Object parameters,
                                                     String className) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + schemeName  + ", find "
                            + parameters.getClass().getName() + ", require"
                            + className);
    }
}