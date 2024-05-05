package com.ggomg.project.base.security.session.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class FormLoginSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {
        // 쿠키 생성
        Cookie sessionCookie = new Cookie("JSESSIONID", request.getSession().getId());
        sessionCookie.setHttpOnly(true);
        sessionCookie.setPath("/");
        sessionCookie.setMaxAge(-1); // 세션 쿠키로 설정 (브라우저 종료 시 사라짐)

        // 쿠키를 응답에 추가
        response.addCookie(sessionCookie);

        // 리다이렉트 대신 ResponseEntity를 사용하여 성공 메시지 반환
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Form Login Success");
        response.getWriter().flush();
    }
}
