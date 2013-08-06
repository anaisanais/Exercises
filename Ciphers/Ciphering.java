package Ciphers;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: NZozulya
 * Date: 5/8/13
 * Time: 2:18 PM
 * To change this template use File | Settings | File Templates.
 */
public class Ciphering {
    //static String CBCTextIV = "4ca00ff4c898d61e1edbf1800618fb28";
    //static String CBCTextIV = "5b68629feb8606f9a6667670b75b38a5";

    static String CTRTextIV = "770b80259ec33beb2561358a9f2dc617";

    public static void main (String[] args) {
        String hello = "Just checking GIt";
        //String CBCText = "28a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
        //String CBCText = "b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
        //String CBCTextB= "28a226d160dad07883d04e008a7897ee";
        //String CTRText = "0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
        String CTRText = "e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
        String CBCText = "28a226d160dad07883d04e008a7897ee";
        String CBCTextB2=  "2e4b7465d5290d0c0e6c6822236e1daa";
        String CBCTextB3 = "fb94ffe0c5da05d9476be028ad7c1d81";
        //byte[] key = HexBin.decode("140b41b22a29beb4061bda66b6747e14");
        //byte[] key = HexBin.decode("140b41b22a29beb4061bda66b6747e14");
        byte[] key = HexBin.decode("36f18357be4dbd77f050515c73fcf9f2");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        byte[] encrypted = HexBin.decode(CTRText);

        //byte[] encrypted = encrypt(secretKeySpec, hello.getBytes());
        byte[] decrypted = decrypt(secretKeySpec,encrypted);

        String s1 = Arrays.toString(decrypted);
        String s2 = new String(decrypted);

        System.out.println(s1);        // -> "[97, 98, 99]"
        System.out.println(s2);
    }

    private static byte[] decrypt(Key key, byte[] textToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            AlgorithmParameterSpec spec = new IvParameterSpec(HexBin.decode(CTRTextIV));
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(textToDecrypt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (InvalidKeyException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (BadPaddingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        return null;
    }

    private static byte[] encrypt(Key key, byte[] textToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(textToEncrypt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (InvalidKeyException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (BadPaddingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        return null;
    }
}
