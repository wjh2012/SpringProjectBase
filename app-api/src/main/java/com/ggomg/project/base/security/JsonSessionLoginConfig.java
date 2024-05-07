package com.ggomg.project.base.security;

import com.ggomg.project.base.security.filter.JsonSessionAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class JsonSessionLoginConfig {

    private final AuthenticationManager authenticationManager;

    @Bean
    public SecurityFilterChain jsonFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/login/session/json/**")
            .csrf(AbstractHttpConfigurer::disable)

            .addFilterAfter(new JsonSessionAuthenticationFilter(authenticationManager),
                LogoutFilter.class)

            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)) // 기본값

            .authorizeHttpRequests((request) -> request
                .requestMatchers("/health", "/login/**").permitAll()
                .anyRequest().authenticated());

        return http.build();
    }
}
