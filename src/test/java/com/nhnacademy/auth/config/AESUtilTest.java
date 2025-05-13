package com.nhnacademy.auth.config;

import com.nhnacademy.auth.exception.DecryptionException;
import com.nhnacademy.auth.exception.EncryptionException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AESUtilTest {

    @Test
    @DisplayName("인코딩 및 디코딩 테스트")
    void testEncryptedAndDecrypted() {
        String test = "test@Password123!";

        String encrypted = AESUtil.encrypt(test);
        String decrypted = AESUtil.decrypt(encrypted);

        Assertions.assertEquals(test, decrypted);
    }

    @Test
    @DisplayName("인코딩 문제시 EncryptionException 발생 여부 확인 테스트.")
    void testEncryptedThrowEncyrptionException() {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES"))
                    .thenThrow(new NoSuchAlgorithmException("mock failure"));

            assertThrows(EncryptionException.class, () -> AESUtil.encrypt("test"));
        }
    }

    @Test
    @DisplayName("Cipher.init 실패 시 EncryptionException 발생")
    void testEncryptInvalidKeyException() throws Exception {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        Cipher mockCipher = Mockito.mock(Cipher.class);

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES")).thenReturn(mockCipher);

            Mockito.doThrow(new InvalidKeyException("Invalid Key"))
                    .when(mockCipher).init(Mockito.eq(Cipher.ENCRYPT_MODE), Mockito.any(Key.class));

            assertThrows(EncryptionException.class, () -> AESUtil.encrypt("test"));
        }
    }

    @Test
    @DisplayName("Cipher.doFinal 실패 시 EncryptionException 발생")
    void testEncryptDoFinalException() throws Exception {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        Cipher mockCipher = Mockito.mock(Cipher.class);

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES")).thenReturn(mockCipher);

            // Cipher.init은 정상 작동하도록 설정
            Mockito.doNothing().when(mockCipher).init(Mockito.eq(Cipher.ENCRYPT_MODE), Mockito.any(Key.class));

            // Cipher.doFinal에서 예외 던지도록 설정
            Mockito.when(mockCipher.doFinal(Mockito.any(byte[].class)))
                    .thenThrow(new BadPaddingException("Bad padding test"));

            assertThrows(EncryptionException.class, () -> AESUtil.encrypt("test"));
        }
    }


    @Test
    @DisplayName("디코딩 문제시 DecryptionException 발생 여부 확인 테스트.")
    void testEncryptedThrowDecryptionException() {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES"))
                    .thenThrow(new NoSuchAlgorithmException("mock failure"));

            assertThrows(DecryptionException.class, () -> AESUtil.decrypt("test"));
        }
    }

    @Test
    @DisplayName("Cipher.init 실패 시 DecryptionException 발생")
    void testDecryptedInvalidKeyException() throws Exception {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        Cipher mockCipher = Mockito.mock(Cipher.class);

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES")).thenReturn(mockCipher);

            Mockito.doThrow(new InvalidKeyException("Invalid Key"))
                    .when(mockCipher).init(Mockito.eq(Cipher.DECRYPT_MODE), Mockito.any(Key.class));

            assertThrows(DecryptionException.class, () -> AESUtil.decrypt("test"));
        }
    }

    @Test
    @DisplayName("Cipher.doFinal 실패 시 DecryptionException 발생")
    void testDecryptDoFinalException() throws Exception {
        ReflectionTestUtils.setField(AESUtil.class, "algorithm", "AES");
        ReflectionTestUtils.setField(AESUtil.class, "secretKey", "1234567890123456");

        Cipher mockCipher = Mockito.mock(Cipher.class);

        try (MockedStatic<Cipher> cipherMock = Mockito.mockStatic(Cipher.class)) {
            cipherMock.when(() -> Cipher.getInstance("AES")).thenReturn(mockCipher);

            // Cipher.init은 정상 작동하도록 설정
            Mockito.doNothing().when(mockCipher).init(Mockito.eq(Cipher.DECRYPT_MODE), Mockito.any(Key.class));

            // Cipher.doFinal에서 예외 던지도록 설정
            Mockito.when(mockCipher.doFinal(Mockito.any(byte[].class)))
                    .thenThrow(new BadPaddingException("Bad padding test"));

            assertThrows(DecryptionException.class, () -> AESUtil.decrypt("test"));
        }
    }

}