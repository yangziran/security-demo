package com.yangziran.security;

import com.google.common.collect.Maps;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * RSA工具类
 * @author yangziran
 * @version 1.0 2021/11/5
 */
public class RsaUtils {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private static final int KEY_SIZE = 2048;
    private static final String PUBLIC_KEY = "PublicKey";
    private static final String PRIVATE_KEY = "PrivateKey";

    private RsaUtils() {}

    /**
     * 生成密钥对
     * @return Map<String, Key> 密钥对
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, Key> generateKey() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Map<String, Key> keyMap = Maps.newHashMap();
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);

        return keyMap;
    }

    /**
     * 获取公钥
     * @param keyMap 密钥对
     * @return String 公钥
     */
    public static String getPublicKey(Map<String, Key> keyMap) {

        Key key = keyMap.get(PUBLIC_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 获取私钥
     * @param keyMap 密钥对
     * @return String 私钥
     */
    public static String getPrivateKey(Map<String, Key> keyMap) {

        Key key = keyMap.get(PRIVATE_KEY);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 还原公钥
     * @param key 公钥字符串
     * @return PublicKey 公钥对象
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PublicKey restorePublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);

        return factory.generatePublic(x509KeySpec);
    }

    /**
     * 还原私钥
     * @param key 私钥字符串
     * @return PrivateKey 私钥对象
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static PrivateKey restorePrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);

        return factory.generatePrivate(pkcs8KeySpec);
    }

    /**
     * 加密
     * @param plaintext 明文
     * @param key 公钥
     * @return String 密文
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String encrypt(String plaintext, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        PublicKey publicKey = restorePublicKey(key);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * 解密
     * @param ciphertext 密文
     * @param key 私钥
     * @return String 明文
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String decrypt(String ciphertext, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        PrivateKey privateKey = restorePrivateKey(key);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] plaintext = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(plaintext, StandardCharsets.UTF_8);
    }

}
