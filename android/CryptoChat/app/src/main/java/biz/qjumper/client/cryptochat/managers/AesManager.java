package biz.qjumper.client.cryptochat.managers;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import biz.qjumper.client.cryptochat.ChatApplication;
import biz.qjumper.client.cryptochat.Constants;

/**
 * Created by sabarishs on 5/19/2019.
 */

public class AesManager {
    private static final String ANDROID_KEY_STORE_NAME = "AndroidKeyStore";
    private static final String KEY_ALIAS = "AES-Internal";
    private static final String RSA_MODE =  "RSA/ECB/PKCS1Padding";
    private static final String CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_RSA = "AndroidOpenSSL";
    private static final int pswdIterations = 10;
    private static final int keySize = 128;
    private static final String cypherInstance = "AES/CBC/PKCS5Padding";
    private static final String secretKeyInstance = "PBKDF2WithHmacSHA1";
    private static final String plainText = "sampleText";
    private static final String AESSalt = "exampleSalt";
    private static final String initializationVector = "8119745113154120";
    private final static Object s_keyInitLock = new Object();
    private static Context mContext = null;

    public static class AesEncryptedData {
        public byte[] encrypted;
        public byte[] iv;
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        System.out.println("decoded aes==>"+ Base64.decode(key, Base64.DEFAULT));
        return Base64.decode(key, Base64.DEFAULT);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.encodeToString(key, Base64.DEFAULT);
    }

    public static byte[] test() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, KeyStoreException, CertificateException, UnrecoverableEntryException {
        final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
        keyGenerator.init(keyGenParameterSpec);
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();
        String textToEncrypt = "Encrypt THIS!";
        byte [] encryption = cipher.doFinal(textToEncrypt.getBytes("UTF-8"));

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(KEY_ALIAS, null);

        secretKey = secretKeyEntry.getSecretKey();

        //cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final IvParameterSpec ivParameterSpec = new IvParameterSpec(cipher.getIV());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        final byte[] decodedData = cipher.doFinal(encryption);

        return decodedData;
    }

    public static void storeKey(String alias, byte[] key) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, KeyStoreException, IllegalBlockSizeException {
        String encStr = Base64.encodeToString(new RsaManager(ChatApplication.INSTANCE.getActivity()).encryptAES(key), Base64.DEFAULT);
        Log.i("GHGH","STORE ENC: "+encStr);
        PersistenceManager.INSTANCE.saveEncryptedAes(alias,encStr);
    }

    public static byte[] getKeyFromStorage(String alias) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, KeyStoreException, IllegalBlockSizeException {
        byte[] decStr = Base64.decode(PersistenceManager.INSTANCE.getEncryptedAes(alias), Base64.DEFAULT);
        Log.i("GHGH","STORE DEC: "+decStr);
        return new RsaManager(ChatApplication.INSTANCE.getActivity()).decryptAES(decStr);
    }

    public static void initKey() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertificateException, IOException {
        KeyStore keyStore = null;
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(KEY_ALIAS, null);
        if (secretKeyEntry == null) {
            Log.i("GHGH","Creating key");
            final KeyGenerator keyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build();
            keyGenerator.init(keyGenParameterSpec);
            SecretKey secretKey = keyGenerator.generateKey();
        }
        keyStore.load(null);
        secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(KEY_ALIAS, null);

        Log.i("GHGH","Done key");
    }

    public static AesEncryptedData encrypt(String stringToEncrypt) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKey secretKey = secretKeyEntry.getSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        AesEncryptedData data = new AesEncryptedData();
        data.encrypted = cipher.doFinal(stringToEncrypt.getBytes("UTF-8"));
        data.iv = cipher.getIV();
        return data;
    }

    public static byte[] decrypt(AesEncryptedData data) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(KEY_ALIAS, null);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKey secretKey = secretKeyEntry.getSecretKey();
        IvParameterSpec ivParameterSpec = new IvParameterSpec(data.iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(data.encrypted);
    }
}
