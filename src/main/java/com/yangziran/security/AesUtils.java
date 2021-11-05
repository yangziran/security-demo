package com.yangziran.security;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * AES工具类
 * @author yangziran
 * @version 1.0 2021/11/5
 */
public class AesUtils {

    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final Integer KEY_SIZE = 256;

    private AesUtils() {}

    /**
     * 生成密钥
     * @return String 密钥
     * @throws NoSuchAlgorithmException
     */
    public static String generateKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(KEY_SIZE);

        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * 加密
     * @param plaintext 明文
     * @param key 密钥
     * @return String 密文
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String encrypt(String plaintext, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = generateCipher(key, Cipher.ENCRYPT_MODE);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * 解密
     * @param ciphertext 密文
     * @param key 密钥
     * @return String 明文
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String decrypt(String ciphertext, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = generateCipher(key, Cipher.DECRYPT_MODE);

        byte[] plaintext = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * 构建Cipher对象
     * @param key 密钥
     * @param opmode 模式
     * @return Cipher
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static Cipher generateCipher(String key, int opmode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        byte[] keys = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keys, KEY_ALGORITHM);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(opmode, secretKeySpec);

        return cipher;
    }

}
