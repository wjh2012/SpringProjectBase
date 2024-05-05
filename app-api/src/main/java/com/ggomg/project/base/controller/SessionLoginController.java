package com.ggomg.project.base.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequestMapping("/login")
@RestController
@RequiredArgsConstructor
public class SessionLoginController {

    private final AuthenticationManager authenticationManager;

    @PostMapping(value = "/session/url", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Object> urlEncodedLogin(LoginRequest loginRequest) {
        Authentication authenticationRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
                loginRequest.password());
        Authentication authenticationResponse =
            this.authenticationManager.authenticate(authenticationRequest);

        if (authenticationResponse.isAuthenticated()) {
            return ResponseEntity.ok("Session UrlEncoded Login Successful");
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("login failed");
    }

    @PostMapping("/session/json")
    public ResponseEntity<Object> jsonLogin(@RequestBody LoginRequest loginRequest) {
        Authentication authenticationRequest =
            UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
                loginRequest.password());
        Authentication authenticationResponse =
            this.authenticationManager.authenticate(authenticationRequest);

        if (authenticationResponse.isAuthenticated()) {
            return ResponseEntity.ok("Session Json Login Successful");
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("login failed");
    }

    public record LoginRequest(String username, String password) {

    }
}
