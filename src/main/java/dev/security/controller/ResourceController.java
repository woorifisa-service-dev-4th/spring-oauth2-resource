package dev.security.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/*
* 리소스 서버에서 JWT (액세스 토큰) 검증을 수행하는 API
*
* 클라이언트(Next.js) -> 인가 서버 (localhost:9000)에서 JWT 발급 -> 리소스 서버 (Spring Boot)에서 토큰 검증
* */
@Slf4j
@RestController
@RequestMapping("/api")
public class ResourceController {

    private final JwtDecoder jwtDecoder;

    // Security에서 제공하는 JWT 디코더
    // 엑세스 토큰 검증, 만료 여부 확인
    public ResourceController(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @GetMapping("/validate-token")
    public Map<String, Object> validateToken(@RequestHeader("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return Map.of(
                    "status", "error",
                    "message", "토큰이 제공되지 않았거나 형식이 잘못되었습니다."
            );
        }

        String accessToken = token.substring(7); // "Bearer " 제거

        try {
            Jwt jwt = jwtDecoder.decode(accessToken); // JWT 유효성 검정 (jwtdecoder.decode())
            return Map.of(
                    "status", "success",
                    "message", "유효한 토큰입니다.",
                    "expiresAt", jwt.getExpiresAt(),
                    "claims", jwt.getClaims()
            );
        } catch (JwtException e) {
            return Map.of(
                    "status", "error",
                    "message", "토큰이 유효하지 않거나 만료되었습니다.",
                    "errorDetails", e.getMessage()
            );
        }
    }
}