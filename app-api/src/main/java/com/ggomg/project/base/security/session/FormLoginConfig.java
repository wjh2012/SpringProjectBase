package com.ggomg.project.base.security.session;

import com.ggomg.project.base.security.session.handler.FormLoginFailureHandler;
import com.ggomg.project.base.security.session.handler.FormLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class FormLoginConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)

            .formLogin((form) -> form
                .loginProcessingUrl("/login/form")
                .successHandler(new FormLoginSuccessHandler())
                .failureHandler(new FormLoginFailureHandler())
                .permitAll())

            .authorizeHttpRequests((request) -> request
                .requestMatchers("/health", "/login/**").permitAll()
                .anyRequest().authenticated());
        SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter();
        SecurityContextHolderFilter securityContextHolderFilter;
        return http.build();
    }
}
