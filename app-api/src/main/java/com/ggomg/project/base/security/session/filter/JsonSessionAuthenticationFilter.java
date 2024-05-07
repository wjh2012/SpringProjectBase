package com.ggomg.project.base.security.session.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ggomg.project.base.security.session.handler.SessionLoginFailureHandler;
import com.ggomg.project.base.security.session.handler.SessionLoginSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class JsonSessionAuthenticationFilter extends
    UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public JsonSessionAuthenticationFilter(AuthenticationManager authenticationManager) {

        this.setFilterProcessesUrl("/login/session/json");
        this.setAuthenticationSuccessHandler(
            new SessionLoginSuccessHandler("Session-JSON login success"));
        this.setAuthenticationFailureHandler(
            new SessionLoginFailureHandler("Session-JSON login failed"));
        this.setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response)
        throws AuthenticationException {
        try {
            BufferedReader reader = request.getReader();
            StringBuilder jsonPayload = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonPayload.append(line);
            }

            LoginRequest loginRequest = objectMapper.readValue(jsonPayload.toString(),
                LoginRequest.class);
            String username = loginRequest.username;
            String password = loginRequest.password;

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username, password);

            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (IOException e) {
            throw new AuthenticationServiceException("JSON 형식 에러", e);
        }
    }

    public record LoginRequest(String username, String password) {

    }
}