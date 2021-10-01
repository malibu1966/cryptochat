package biz.qjumper.client.cryptochat.managers;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by sabarishs on 5/19/2019.
 */

public class AesManager {
    private static final int pswdIterations = 10;
    private static final int keySize = 128;
    private static final String cypherInstance = "AES/CBC/PKCS5Padding";
    private static final String secretKeyInstance = "PBKDF2WithHmacSHA1";
    private static final String plainText = "sampleText";
    private static final String AESSalt = "exampleSalt";
    private static final String initializationVector = "8119745113154120";
    private static final String SHARED_PREFERENCE_NAME = "unwaitSharedPrefs";
    private static final String ENCRYPTED_KEY_NAME = "internalAESkey";
    public static byte[] decryptBASE64(String key) throws Exception {
        System.out.println("decoded aes==>"+ Base64.decode(key, Base64.DEFAULT));
        return Base64.decode(key, Base64.DEFAULT);
    }
    Context mContext = null;

//    public static String encryptBASE64(byte[] key) throws Exception {
//        return Base64.encodeToString(key, Base64.DEFAULT);
//    }

    public AesManager (Context context) {
        mContext = context;
    }

    public byte[] getInternalKey() {
        SharedPreferences sharedPreferences = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String b64_key = sharedPreferences.getString(ENCRYPTED_KEY_NAME,null);
        if (b64_key == null)
            return null;
        else
            return Base64.decode(b64_key, Base64.DEFAULT);
    }

    public void storeInternalKey(byte[] key) {
        SharedPreferences sharedPreferences = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor shed = sharedPreferences.edit();
        shed.putString(ENCRYPTED_KEY_NAME, Base64.encodeToString(key, Base64.DEFAULT));
        shed.commit();
    }

    public String decrypt(String _cipherData, String _iv) {
        byte[] cipherData = Base64.decode(_cipherData, Base64.DEFAULT);
        byte[] iv = Base64.decode(_iv, Base64.DEFAULT);
        String decryptedText = "";
        try {
            Cipher cipher_aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(getInternalKey(),"AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher_aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedBytes = cipher_aes.doFinal(cipherData);
            decryptedText = new String(decryptedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return decryptedText;
    }

//    public static String encrypt(String textToEncrypt, String key, String iv) throws Exception {
//        byte[] encodedKey     = decryptBASE64(key);
//        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
//        //Get Cipher Instance
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//
//        //Create SecretKeySpec
//        SecretKeySpec keySpec = new SecretKeySpec(originalKey.getEncoded(), "AES");
//
//        //Create IvParameterSpec
//        IvParameterSpec ivSpec = new IvParameterSpec(decryptBASE64(iv));
//
//        //Initialize Cipher for ENCRYPT_MODE
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
//
//        //Perform Encryption
//        byte[] cipherText = cipher.doFinal(textToEncrypt.getBytes());
//
//        return encryptBASE64(cipherText);
//    }
//
//    public static String decrypt(String textToDecrypt) throws Exception {
//
//        byte[] encryted_bytes = Base64.decode(textToDecrypt, Base64.DEFAULT);
//        SecretKeySpec skeySpec = new SecretKeySpec(getRaw(plainText, AESSalt), "AES");
//        Cipher cipher = Cipher.getInstance(cypherInstance);
//        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(initializationVector.getBytes()));
//        byte[] decrypted = cipher.doFinal(encryted_bytes);
//        return new String(decrypted, "UTF-8");
//    }
//
//    private static byte[] getRaw(String plainText, String salt) {
//        try {
//            SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKeyInstance);
//            KeySpec spec = new PBEKeySpec(plainText.toCharArray(), decryptBASE64(salt), pswdIterations, keySize);
//            return factory.generateSecret(spec).getEncoded();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return new byte[0];
//    }
}
