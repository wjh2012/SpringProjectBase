package com.ggomg.project.base.security.session.formLogin.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class FormLoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // HTTP 응답을 직접 설정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("Form Login Failed");
        response.getWriter().flush();
    }
}
