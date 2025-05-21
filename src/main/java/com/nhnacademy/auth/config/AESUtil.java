package com.nhnacademy.auth.config;

import com.nhnacademy.auth.exception.DecryptionException;
import com.nhnacademy.auth.exception.EncryptionException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * AES: 암호화 알고리즘 중 하나입니다. DES를 보완한 기술로 데이터를 128비트 블록으로 나눈 다음 수학적 연산들을 이용해 암호 블록으로 변환하는 방식입니다.
 * AES 알고리즘을 사용하여 암호화 및 복호화를 하는 Util 입니다.
 * javax.crypto를 사용해, Spring Security를 사용하지 않는 서비스에서도 사용 가능합니다.
 */
@Component
public class AESUtil {
    /**
     * 오타 방지용.
     * 사용할 알고리즘.
     */
    @Value("${aes.algorithm}")
    @SuppressWarnings("java:S7178")
    private String algorithmProp;

    /**
     * 암호화 및 복호화시에 사용될 정의 키.
     */
    @Value("${aes.key}")
    @SuppressWarnings("java:S7178")
    private String secretKeyProp;

    /**
     * Cipher에 들어갈 static 알고리즘 값.
     */
    private static String algorithm;

    /**
     * Cipher에 들어갈 static 비밀키 값.
     */
    private static String secretKey;

    @PostConstruct
    @SuppressWarnings("java:S2696")
    public void init() {
        algorithm = algorithmProp;
        secretKey = secretKeyProp;
    }

    /**
     * 1. secretKey를 바이트 배열로 변환 후 AES에 맞는 비밀키 객체를 생성한다.
     * 2. AES에 맞는 Cipher 인스턴스(암호화 및 복호화를 위한 암호 기능 제공)를 가져온다.
     * 3. 암호화 모드로 Cipher 객체를 초기화 하고 앞서 생성한 키를 설정한다.
     * 4. 평면 문자열을 바이트로 변환 후 암호화 를 수행함.
     * 5. 암호화된 바이트 배열을 Base64로 인코딩해 사람이 읽을 수 있는 문자열로 반환한다.
     *
     * @param input 인코딩 할 Text.
     * @return 인코딩 된 text값.
     */
    public static String encrypt(String input) {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException(e.getMessage(), e);
        }
        try {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } catch (InvalidKeyException e) {
            throw new EncryptionException(e.getMessage(), e);
        }
        byte[] encryptedBytes;
        try {
            encryptedBytes = cipher.doFinal(input.getBytes());
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException(e.getMessage(), e);
        }
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * 1. 복호화를 위한 키 객체를 생성한다. encrypt와 동일한 키를 사용해야 정상적으로 복호화 된다.
     * 2. 해당 알고리즘을 위한 Cipher 객체를 가져온다.
     * 3. 복호화 모드로 Cipher를 초기화 한다.
     * 4. 암호화된 문자열을 Base64로 디코딩해 바이트 배열로 변환한다.
     * 5. 암호화된 바이트배열을 복호화 해 원래의 바이트 배열(평문)으로 되돌린다.
     * 6. 원래의 평문 문자열로 반환한다.
     *
     * @param encryptedInput 인코딩 된 Text.
     * @return 디코딩 된 text값.
     */
    public static String decrypt(String encryptedInput) {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new DecryptionException(e.getMessage(), e);
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } catch (InvalidKeyException e) {
            throw new DecryptionException(e.getMessage(), e);
        }
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedInput);
        byte[] decryptedBytes;
        try {
            decryptedBytes = cipher.doFinal(encryptedBytes);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new DecryptionException(e.getMessage(), e);
        }
        return new String(decryptedBytes);
    }
}
