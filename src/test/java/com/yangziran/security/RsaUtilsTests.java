package com.yangziran.security;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * RSA工具类测试
 * @author yangziran
 * @version 1.0 2021/11/5
 */
class RsaUtilsTests {

    static final String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1C7IX7Z9DfOiEDQBUdM4EtES4rBtuBPvWZtp6qacu4zEJlPcEe/4RjJFRObDgYecsPnFr8Q6W0+b9hA+MI3XzeQ4XEb7wEWXyp7MJfjz2bMdk0fFdmZ0IILxnONtvZmrJ9yhiWIjCvI8lbASZyWy/byKK5sOr8iU3shQ+WUzatxJA7650ikwGVpmiORTuTd0FgwA92Ixp2gLhMzdSH/XCMWdAvMBwA7nn8181F+HKZVfTZ+ny65FlBIJyJj7SNd3Sj2QLISu6cXaYXMWQsxPFXoWASazh+Rpx+/sYJDrEVWhjhGSgCOx2jMseTVGvogKOSD5Tvlz9N2GN3aEAs3pfwIDAQAB";
    static final String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDULshftn0N86IQNAFR0zgS0RLisG24E+9Zm2nqppy7jMQmU9wR7/hGMkVE5sOBh5yw+cWvxDpbT5v2ED4wjdfN5DhcRvvARZfKnswl+PPZsx2TR8V2ZnQggvGc4229masn3KGJYiMK8jyVsBJnJbL9vIormw6vyJTeyFD5ZTNq3EkDvrnSKTAZWmaI5FO5N3QWDAD3YjGnaAuEzN1If9cIxZ0C8wHADuefzXzUX4cplV9Nn6fLrkWUEgnImPtI13dKPZAshK7pxdphcxZCzE8VehYBJrOH5GnH7+xgkOsRVaGOEZKAI7HaMyx5NUa+iAo5IPlO+XP03YY3doQCzel/AgMBAAECggEBAJXYkCOgEgLnWz2MLJ5nx4LqaibzqBjG41LqAcv4bFm7WM8kjBeS3EheujKlsc5pQkxtqKGvt/LCbwdAg1rw4UYDdZYdfy9TNpaevNfYUAYfi7R2jEpIopxPPWip6NdsjcYx91a5mrvhRM4FsYlsw1KUcxPGhoG36wLGfwER6lT9ATtxW30YvmC59vxx4fNplyW3dIy45mtQtRrdnq5iAhvH8aoY2dl003a2gxP+z1fCpb4iXC8ceg+pc9fFIx/RqWTsuXUYIeup0Glyqt/h0FAQ3JdsFqTXHFdBrSuqEU006hOU7bq8rrCwS5eoKUy8WRGbwHVpBu57/7ccLIeJy9kCgYEA96gWjAv+3UL01vPGgti2ev/4Fy47GJAdU9IA/ZEwu4X8jXhHUei/HYO6aZevzCXR0mLlNHiS1yXYxlwpDZ3xU+tFnH3lQb7FdFnmqMXhg42omrYsr7Qbn5ACrqw9m2GfoMmWjybYiGIOFKuPd61I8avZhXoXoheYkkSA83m87lMCgYEA21TAMhMofuQLuZKwYnvfNGroAr3Shn29Zh8MfeLKmX71IA691FhfaPZhLTsYFek963DK7oHTUJVgSeTS2rIijHMB5RSuVTl+py4OZdRqsQ8Wi8H1tK6Q+q5CyLZcDmfgTzruTxmr7YJZmsKPG+3o3wzEul1IuFoGk5ybYAGguqUCgYBfZ8qf0vMxC91EfY7o01GhGsDZNT8g3EvgAZPOG0O5ygkb+s0G2fHeDeQfT4cyzxMAyIZh610uMu9KozBRhZn1aTpc6gcKh9KLWyLHu8t/oW/lge6/FVRa6OCPp9zn4fjbuS0eIqniCFxCTEEtqnziVQCsMfeuwwZMusUuhqRo7wKBgAaYpusanmYqj5u2KK3dkdnuuSmT8efvkimnF2YV0wgIxHCBYP4o5j2u4z9L/q5yBFW3X7MKnoNW6r1uL1U6dEWLE+yC0bdockGu5en0GH1YudHcNHqJoXyYjxOgQGaCg0F+wToJyJztBarc3Rb28cD7jlMYiR5aPsZjuFyLz/ytAoGARJBDAYugbKh0Cahm3Hm7d3S8Y+KaoCmJ6PXjTIECTOOB/5Dh69UWEQhO+EGFxpWf2c8s3j7pY1mjch+7av+A5KmOGSa+lth7XqN7VS3QpeYQbjzGdoVPHBd9zCU+EstUPXGlTE4Dq3TB5m2YCXz9mUH2Loo7omzhZyMZOhfWIGk=";
    static final String CONST_PLAINTEXT = "测试";
    static final String CONST_CIPHERTEXT = "s6YlGV8vH4NirksGG9XNS++FNPqoH1dl/EesPH0wP7m69JaC8m1cXMA9aKR4TOMMPPNDqh26ZW6eDG3C+JbdaREbaQKPnC57//g/xBrfIUto8qkdkla0B95iQfNL/i6u1t/+xVxwD/bXI6ksM5aghqsIHejPqcOGAfDQ1D5fwcqRF08AQvO4OEtOR8tRwAvjpqyeoLzbDCu9CX5AF7H3fakkKvy2vRblW6iLSFahi5OSUSLi+wLgL0jnj+T7MkgYnC8n8NvHd4TXl+F3golhjEUUloRiEjemRUZZ0hM3nETMvg79vIlDKOwQOmkCC9hUcST3AEovIZSx+Oyq+EqBbg==";

    @Test
    void generateKey() throws NoSuchAlgorithmException {

        Map<String, Key> keyMap = RsaUtils.generateKey();
        assertNotNull(keyMap);

        String publicKey = RsaUtils.getPublicKey(keyMap);
        assertNotNull(publicKey);
        System.out.println("公钥为: " + publicKey);

        String privateKey = RsaUtils.getPrivateKey(keyMap);
        assertNotNull(privateKey);
        System.out.println("私钥为: " + privateKey);
    }

    @Test
    void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String ciphertext = RsaUtils.encrypt(CONST_PLAINTEXT, PUBLIC_KEY);
        System.out.println("密文为: " + ciphertext);
    }

    @Test
    void decrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String plaintext = RsaUtils.decrypt(CONST_CIPHERTEXT, PRIVATE_KEY);
        System.out.println("明文为: " + plaintext);
    }

}
