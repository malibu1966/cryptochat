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
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by sabarishs on 5/16/2019.
 */

public class RsaManager {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    private static final String ANDROID_KEY_STORE_NAME = "AndroidKeyStore";
    private static final String AES_MODE_M_OR_GREATER = "AES/GCM/NoPadding";
    private static final String AES_MODE_LESS_THAN_M = "AES/ECB/PKCS7Padding";
    private static final String KEY_ALIAS = "UnwaitKeyAlias";
    // TODO update these bytes to be random for IV of encryption
    private static final byte[] FIXED_IV = new byte[]{ 55, 54, 53, 52, 51, 50,
            49, 48, 47,
            46, 45, 44 };
    private static final String CHARSET_NAME = "UTF-8";
    private static final String RSA_ALGORITHM_NAME = "RSA";
    private static final String RSA_MODE =  "RSA/ECB/PKCS1Padding";
    private static final String CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_RSA = "AndroidOpenSSL";
    private static final String CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_AES = "BC";
    private static final String SHARED_PREFERENCE_NAME = "YOUR-EncryptedKeysSharedPreferences";
    private static final String ENCRYPTED_KEY_NAME = "YOUR-EncryptedKeysKeyName";
    private static final String LOG_TAG = "GHGH";

    private final static Object s_keyInitLock = new Object();
    Context mContext = null;

    public RsaManager(Context c) {
        mContext = c;
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.decode(key, Base64.DEFAULT);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.encodeToString(key, Base64.DEFAULT);
    }

//
    public static String sign(byte[] data) throws Exception {
        KeyStore keystore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keystore.load(null);
        Key key = keystore.getKey(KEY_ALIAS,null);
        KeyPair keyPair = null;
//        String privateKey = encryptBASE64(key.getEncoded());
//        byte[] keyBytes = decryptBASE64(privateKey);
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(KEY_ALIAS);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            keyPair =  new KeyPair(publicKey, (PrivateKey) key);
        }

        //PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key.getEncoded());

        //KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        //PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        PrivateKey privKey = (PrivateKey) key;
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }
//
//
//    public static boolean verify(byte[] data, String publicKey, String sign)
//            throws Exception {
//
//        byte[] keyBytes = decryptBASE64(publicKey);
//
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//
//        PublicKey pubKey = keyFactory.generatePublic(keySpec);
//
//        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
//        signature.initVerify(pubKey);
//        signature.update(data);
//
//        return signature.verify(decryptBASE64(sign));
//    }
//
//
//    public static String decryptByPrivateKey(String data)
//            throws Exception {
//
//        byte[] keyBytes = decryptBASE64(PreferenceManager.getInstance().getPrivateKey(QJumperApplication.getInstance().getContext()));
//
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
//
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//        String str = new String(cipher.doFinal(decryptBASE64(data)), "UTF-8");
//        System.out.println("decryptedData===>"+str);
//        return str;
//    }
//
//
//    public static String decryptByPublicKey(String data, String key)
//            throws Exception {
//
//        byte[] keyBytes = decryptBASE64(PreferenceManager.getInstance().getPublicKey(QJumperApplication.getInstance().getContext()));
//
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key publicKey = keyFactory.generatePublic(x509KeySpec);
//
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, publicKey);
//        String str = new String(cipher.doFinal(decryptBASE64(data)),"utf-8");
//        System.out.println("decryptedData===>"+str);
//        return str;
//    }
//
//
//    public static String encryptByPublicKey(String data, String key)
//            throws Exception {
//
//        byte[] keyBytes = decryptBASE64(key);
//
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key publicKey = keyFactory.generatePublic(x509KeySpec);
//
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return encryptBASE64(cipher.doFinal(decryptBASE64(data)));
//    }
//
//
//    public static byte[] encryptByPrivateKey(byte[] data, String key)
//            throws Exception {
//
//        byte[] keyBytes = decryptBASE64(key);
//
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
//
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
//
//        return cipher.doFinal(data);
//    }
//
//    public static String getPrivateKey(Map<String, Object> keyMap)
//            throws Exception {
//        Key key = (Key) keyMap.get(PRIVATE_KEY);
//
//        return encryptBASE64(key.getEncoded());
//    }
//
//    public static String getPublicKey(Map<String, Object> keyMap)
//            throws Exception {
//        Key key = (Key) keyMap.get(PUBLIC_KEY);
//
//        return encryptBASE64(key.getEncoded());
//    }
//
//
   // public Map<String, Object> initKey() throws Exception {
//        KeyPairGenerator keyPairGen = KeyPairGenerator
//                .getInstance(KEY_ALGORITHM);
//        keyPairGen.initialize(2048);
//
//        KeyPair keyPair = keyPairGen.generateKeyPair();
//
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//
//        Map<String, Object> keyMap = new HashMap<String, Object>(2);
//        byte[] encodedPublicKey = publicKey.getEncoded();
//        String pubKey = Base64.encodeToString(encodedPublicKey,0);
//        byte[] encodedPrivKey = privateKey.getEncoded();
//        String privKey = Base64.encodeToString(encodedPrivKey,0);
//        Calendar cal= Calendar.getInstance();
//        cal.add(Calendar.DATE, 30);
//        //PreferenceManager.setPublicKeyExpiry(QJumperApplication.getInstance().getContext(),cal.getTimeInMillis());
//        //PreferenceManager.getInstance().setPublicKey(QJumperApplication.getInstance().getContext(),pubKey);
//        //PreferenceManager.getInstance().setPrivateKey(QJumperApplication.getInstance().getContext(),privKey);
//        keyMap.put(PUBLIC_KEY, publicKey.toString());
//        keyMap.put(PRIVATE_KEY, privateKey);
//        return keyMap;
    //}
//
//    public static PublicKey getPublicKey(String MODULUS, String EXPONENT) throws Exception {
//        byte[] modulusBytes = Base64.decode(MODULUS,0);
//        byte[] exponentBytes = Base64.decode(EXPONENT,0);
//
//        BigInteger modulus = new BigInteger(1, (modulusBytes) );
//        BigInteger exponent = new BigInteger(1, (exponentBytes));
//
//        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
//        KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
//        return kf.generatePublic(spec);
//    }
//
//    public static String getPublicKey() throws Exception {
//      if(PreferenceManager.getInstance().getPublicKeyExpiry(QJumperApplication.getInstance().getContext())- System.currentTimeMillis()<=0)
//      {
//          initKey();
//      }
//      return PreferenceManager.getInstance().getPublicKey(QJumperApplication.getInstance().getContext());
//    }
//
//    public static byte[] encrypt(Key publicKey, String s) throws Exception {
//        byte[] byteData = s.getBytes();
//        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedData = cipher.doFinal(byteData);
//
//
//        return encryptedData;
//    }
//

    // Using algorithm as described at https://medium.com/@ericfu/securely-storing-secrets-in-an-android-application-501f030ae5a3
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void initKeys() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            initValidKeys();
        } else {
            boolean keyValid = false;
            try {
                KeyStore.Entry keyEntry = keyStore.getEntry(KEY_ALIAS, null);
                if (keyEntry instanceof KeyStore.SecretKeyEntry &&
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    keyValid = true;
                }

                if (keyEntry instanceof KeyStore.PrivateKeyEntry && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    String secretKey = getSecretKeyFromSharedPreferences();
                    // When doing "Clear data" on Android 4.x it removes the shared preferences (where
                    // we have stored our encrypted secret key) but not the key entry. Check for existence
                    // of key here as well.
                    if (!TextUtils.isEmpty(secretKey)) {
                        keyValid = true;
                    }
                }
            } catch (NullPointerException | UnrecoverableKeyException e) {
                // Bad to catch null pointer exception, but looks like Android 4.4.x
                // pin switch to password Keystore bug.
                // https://issuetracker.google.com/issues/36983155
                Log.e(LOG_TAG, "Failed to get key store entry", e);
            }

            if (!keyValid) {
                synchronized (s_keyInitLock) {
                    // System upgrade or something made key invalid
                    removeKeys(keyStore);
                    initValidKeys();
                }
            }

        }

    }

    protected void removeKeys(KeyStore keyStore) throws KeyStoreException {
        keyStore.deleteEntry(KEY_ALIAS);
        removeSavedSharedPreferences();
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void initValidKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertificateException, UnrecoverableEntryException, NoSuchPaddingException, KeyStoreException, InvalidKeyException, IOException {
        synchronized (s_keyInitLock) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generateKeysForAPIMOrGreater();
            } else {
                generateKeysForAPILessThanM();
            }
        }
    }

    @SuppressLint("ApplySharedPref")
    private void removeSavedSharedPreferences() {
        SharedPreferences sharedPreferences = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        boolean clearedPreferencesSuccessfully = sharedPreferences.edit().clear().commit();
        Log.d(LOG_TAG, String.format("Cleared secret key shared preferences `%s`", clearedPreferencesSuccessfully));
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void generateKeysForAPILessThanM() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, CertificateException, UnrecoverableEntryException, NoSuchPaddingException, KeyStoreException, InvalidKeyException, IOException {
        // Generate a key pair for encryption
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 30);
        AlgorithmParameterSpec spec;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M){
            spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT)
                    .setCertificateSubject(new X500Principal("CN=" + KEY_ALIAS))
                    .setCertificateSerialNumber(BigInteger.TEN)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .build();
        } else {
            spec = new KeyPairGeneratorSpec.Builder(mContext)
                    .setAlias(KEY_ALIAS)
                    .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME, ANDROID_KEY_STORE_NAME);
        kpg.initialize(spec);
        kpg.generateKeyPair();
        saveEncryptedKey();
    }

    @SuppressLint("ApplySharedPref")
    private void saveEncryptedKey() throws CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException, IOException {
        SharedPreferences pref = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        String encryptedKeyBase64encoded = pref.getString(ENCRYPTED_KEY_NAME, null);
        if (encryptedKeyBase64encoded == null) {
            byte[] key = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(key);
            byte[] encryptedKey = rsaEncryptKey(key);
            encryptedKeyBase64encoded = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
            SharedPreferences.Editor edit = pref.edit();
            edit.putString(ENCRYPTED_KEY_NAME, encryptedKeyBase64encoded);
            boolean successfullyWroteKey = edit.commit();
            if (successfullyWroteKey) {
                Log.d(LOG_TAG, "Saved keys successfully");
            } else {
                Log.e(LOG_TAG, "Saved keys unsuccessfully");
                throw new IOException("Could not save keys");
            }
        }

    }

    public String getPublicKey() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        if (privateKey == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE_NAME);
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_DECRYPT)
                            .setKeySize(2048)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), new OAEPParameterSpec("SHA-256",
//                    "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            //            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), new OAEPParameterSpec("SHA-256",
//                    "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
            // The key pair can also be obtained from the Android Keystore any time as follows:
            privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        }
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        byte[] publicKeyBytes = Base64.encode(publicKey.getEncoded(), Base64.DEFAULT);
        String pubKey = new String(publicKeyBytes);
        Log.i("GHGH","-----BEGIN PUBLIC KEY-----\n"+pubKey+"-----END PUBLIC KEY-----");
        return "-----BEGIN PUBLIC KEY-----\n"+pubKey+"-----END PUBLIC KEY-----";
    }

    public byte[] decryptAES(String encryptedData) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        KeyStore keystore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        KeyPair keyPair = null;
        keystore.load(null);
        Key key = keystore.getKey(KEY_ALIAS,null);
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(KEY_ALIAS);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
           keyPair =  new KeyPair(publicKey, (PrivateKey) key);
        }
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        try {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), new OAEPParameterSpec("SHA-256",
                    "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        byte[] mydata = cipher.doFinal(Base64.decode(encryptedData, Base64.DEFAULT));
        Log.i("GHGH","Done decryption");
        return mydata;
    }

    private Key getSecretKeyAPILessThanM() throws CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException, IOException {
        String encryptedKeyBase64Encoded = getSecretKeyFromSharedPreferences();
        if (TextUtils.isEmpty(encryptedKeyBase64Encoded)) {
            throw new InvalidKeyException("Saved key missing from shared preferences");
        }
        byte[] encryptedKey = Base64.decode(encryptedKeyBase64Encoded, Base64.DEFAULT);
        byte[] key = rsaDecryptKey(encryptedKey);
        return new SecretKeySpec(key, "AES");
    }

    private String getSecretKeyFromSharedPreferences() {
        SharedPreferences sharedPreferences = mContext.getSharedPreferences(SHARED_PREFERENCE_NAME, Context.MODE_PRIVATE);
        return sharedPreferences.getString(ENCRYPTED_KEY_NAME, null);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    protected void generateKeysForAPIMOrGreater() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator;
        keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE_NAME);
        keyGenerator.init(
                new KeyGenParameterSpec.Builder(KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        // NOTE no Random IV. According to above this is less secure but acceptably so.
                        .setRandomizedEncryptionRequired(false)
                        .build());
        // Note according to [docs](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html)
        // this generation will also add it to the keystore.
        keyGenerator.generateKey();
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    public String encryptData(String stringDataToEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {

        initKeys();

        if (stringDataToEncrypt == null) {
            throw new IllegalArgumentException("Data to be decrypted must be non null");
        }

        Cipher cipher;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(AES_MODE_M_OR_GREATER);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyAPIMorGreater(),
                    new GCMParameterSpec(128, FIXED_IV));
        } else {
            cipher = Cipher.getInstance(AES_MODE_LESS_THAN_M, CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_AES);
            try {
                cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyAPILessThanM());
            } catch (InvalidKeyException | IOException | IllegalArgumentException e) {
                // Since the keys can become bad (perhaps because of lock screen change)
                // drop keys in this case.
                removeKeys();
                throw e;
            }
        }

        byte[] encodedBytes = cipher.doFinal(stringDataToEncrypt.getBytes(CHARSET_NAME));
        String encryptedBase64Encoded = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        return encryptedBase64Encoded;

    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    public String decryptData(String encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, KeyStoreException, IOException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException {

        initKeys();

        if (encryptedData == null) {
            throw new IllegalArgumentException("Data to be decrypted must be non null");
        }

        byte[] encryptedDecodedData = Base64.decode(encryptedData, Base64.DEFAULT);

        Cipher c;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                c = Cipher.getInstance(AES_MODE_M_OR_GREATER);
                c.init(Cipher.DECRYPT_MODE, getSecretKeyAPIMorGreater(), new GCMParameterSpec(128, FIXED_IV));
            } else {
                c = Cipher.getInstance(AES_MODE_LESS_THAN_M, CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_AES);
                c.init(Cipher.DECRYPT_MODE, getSecretKeyAPILessThanM());
            }
        } catch (InvalidKeyException | IOException e) {
            // Since the keys can become bad (perhaps because of lock screen change)
            // drop keys in this case.
            removeKeys();
            throw e;
        }

        byte[] decodedBytes = c.doFinal(encryptedDecodedData);
        return new String(decodedBytes, CHARSET_NAME);

    }

    private Key getSecretKeyAPIMorGreater() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);
        return keyStore.getKey(KEY_ALIAS, null);

    }

    private byte[] rsaEncryptKey(byte[] secret) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, NoSuchPaddingException, UnrecoverableEntryException, InvalidKeyException {

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_RSA);
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        byte[] encryptedKeyAsByteArray = outputStream.toByteArray();
        return encryptedKeyAsByteArray;
    }

    private  byte[] rsaDecryptKey(byte[] encrypted) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
        keyStore.load(null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);
        Cipher output = Cipher.getInstance(RSA_MODE, CIPHER_PROVIDER_NAME_ENCRYPTION_DECRYPTION_RSA);
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte)nextByte);
        }

        byte[] decryptedKeyAsBytes = new byte[values.size()];
        for(int i = 0; i < decryptedKeyAsBytes.length; i++) {
            decryptedKeyAsBytes[i] = values.get(i);
        }
        return decryptedKeyAsBytes;
    }

    public void removeKeys() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        synchronized (s_keyInitLock) {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE_NAME);
            keyStore.load(null);
            removeKeys(keyStore);
        }
    }
}
