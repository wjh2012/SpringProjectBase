package com.ggomg.project.base.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SessionConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)

            .cors(Customizer.withDefaults())

            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests((request) -> request
                .requestMatchers("/health", "/login").permitAll()
                .anyRequest().authenticated())

            .oauth2ResourceServer((oauth2) -> oauth2
                .jwt(Customizer.withDefaults()))

            .exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));

        return http.build();
    }
}
