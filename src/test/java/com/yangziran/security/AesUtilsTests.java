package com.yangziran.security;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AES工具类测试
 * @author yangziran
 * @version 1.0 2021/11/5
 */
class AesUtilsTests {

    static final String CONST_KEY = "7j43rxXuU+ZroSZNo4txO7XnWVBrBXrOkbaHA9AA+Qo=";
    static final String CONST_PLAINTEXT = "测试";
    static final String CONST_CIPHERTEXT = "l1NmPcTJtpDV0LJ+FBp5cQ==";

    @Test
    void generateKey() throws NoSuchAlgorithmException {

        String key = AesUtils.generateKey();
        assertNotNull(key);
        System.out.println(key);
    }

    @Test
    void encrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        String ciphertext = AesUtils.encrypt(CONST_PLAINTEXT, CONST_KEY);
        assertNotNull(ciphertext);
        System.out.println(ciphertext);
        assertEquals(ciphertext, CONST_CIPHERTEXT);
    }

    @Test
    void decrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        String plaintext = AesUtils.decrypt(CONST_CIPHERTEXT, CONST_KEY);
        assertNotNull(plaintext);
        System.out.println(plaintext);
        assertEquals(plaintext, CONST_PLAINTEXT);
    }

}
