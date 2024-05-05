package com.ggomg.project.base.security.session.formLogin;

import com.ggomg.project.base.security.session.formLogin.handler.FormLoginFailureHandler;
import com.ggomg.project.base.security.session.formLogin.handler.FormLoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class FormLoginConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)

            .cors(Customizer.withDefaults())

            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)) // 기본값

            .securityContext((securityContext) -> securityContext
                    .securityContextRepository(new HttpSessionSecurityContextRepository()))

            .formLogin((form) -> form
                    .loginProcessingUrl("/login/form")
                    .successHandler(new FormLoginSuccessHandler())
                    .failureHandler(new FormLoginFailureHandler())
                    .permitAll())

            .authorizeHttpRequests((request) -> request
                .requestMatchers("/health", "/login/**").permitAll()
                .anyRequest().authenticated());

        return http.build();
    }
}
