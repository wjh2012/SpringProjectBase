package com.ggomg.project.base.security.filter;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

@Slf4j
public class JwtAuthenticationFilter extends BearerTokenAuthenticationFilter {

    public JwtAuthenticationFilter(
        AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
        super(authenticationManagerResolver);
    }

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }
}
