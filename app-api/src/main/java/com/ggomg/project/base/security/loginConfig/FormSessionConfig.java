package com.ggomg.project.base.security.loginConfig;

import com.ggomg.project.base.security.handler.SessionLoginFailureHandler;
import com.ggomg.project.base.security.handler.SessionLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class FormSessionConfig {

    @Bean
    public SecurityFilterChain formFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/login/session/form/**")

            .csrf(AbstractHttpConfigurer::disable)

            .authorizeHttpRequests((request) -> request
                .anyRequest().authenticated())

            .formLogin((form) -> form
                .loginProcessingUrl("/login/session/form")
                .successHandler(new SessionLoginSuccessHandler("Session-Form login success"))
                .failureHandler(new SessionLoginFailureHandler("Session-Form login failed")))

            .exceptionHandling(exceptionConfig -> exceptionConfig
                .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .accessDeniedHandler(new AccessDeniedHandlerImpl()));

        return http.build();
    }
}
