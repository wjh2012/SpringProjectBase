package com.ggomg.project.base.controller;

import java.time.Instant;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping("/login")
@RestController
@RequiredArgsConstructor
public class TokenLoginController {

    private final AuthenticationManager authenticationManager;
    private final JwtEncoder encoder;

    @GetMapping("/token")
    public ResponseEntity<Object> login(@RequestParam("username") String username,
        @RequestParam("password") String password) {
        Authentication authenticationRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(username,
                password);
        Authentication authenticationResponse =
            this.authenticationManager.authenticate(authenticationRequest);

        if (authenticationResponse.isAuthenticated()) {
            Instant now = Instant.now();
            long expiry = 36000L;
            String scope = authenticationResponse.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
            JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(authenticationResponse.getName())
                .claim("scope", scope)
                .build();
            String jwtToken = this.encoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();

            ResponseCookie cookie = ResponseCookie.from("auth_token", jwtToken)
                .httpOnly(true) // 쿠키를 자바스크립트에서 접근하지 못하도록 함
                .secure(true) // HTTPS를 통해서만 쿠키를 전송
                .path("/") // 모든 경로에서 쿠키 사용
                .maxAge(expiry) // 쿠키 만료 시간
                .sameSite("Strict") // CSRF 공격 방지
                .build();

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.SET_COOKIE, cookie.toString());

            return ResponseEntity.ok().headers(headers).body(jwtToken);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("login failed");
    }

    @PostMapping("/token")
    public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {
        Authentication authenticationRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
                loginRequest.password());
        Authentication authenticationResponse =
            this.authenticationManager.authenticate(authenticationRequest);

        if (authenticationResponse.isAuthenticated()) {
            Instant now = Instant.now();
            long expiry = 36000L;
            String scope = authenticationResponse.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
            JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(authenticationResponse.getName())
                .claim("scope", scope)
                .build();
            return ResponseEntity.ok(
                this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue());
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("login failed");
    }

    public record LoginRequest(String username, String password) {

    }

}
