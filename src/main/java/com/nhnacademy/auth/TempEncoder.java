package com.nhnacademy.auth;

// 임시 코드 예시 (예: 테스트 코드나 main 메서드)
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class TempEncoder {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String rawPassword = "Aa!12345678";
        String encodedPassword = encoder.encode(rawPassword);
        System.out.println("Raw: " + rawPassword);
        System.out.println("Encoded: " + encodedPassword);
        // 예: Encoded: $2a$10$abcdefghijklmnopqrstuvwxyzABCDEFG1234567890./
    }
}
