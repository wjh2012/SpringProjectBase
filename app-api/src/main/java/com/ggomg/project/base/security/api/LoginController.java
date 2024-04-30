package com.ggomg.project.base.security.api;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

  private final AuthenticationManager authenticationManager;

  @PostMapping("/login")
  public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {
    Authentication authenticationRequest =
        UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
            loginRequest.password());
    Authentication authenticationResponse =
        this.authenticationManager.authenticate(authenticationRequest);
    return ResponseEntity.status(HttpStatus.OK).body("health ok");
  }

  public record LoginRequest(String username, String password) {
    
  }
}
