package com.ggomg.project.base.config;

import com.ggomg.project.base.config.exceptionHandling.RestAccessDeniedHandler;
import com.ggomg.project.base.config.exceptionHandling.RestAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

  private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
  private final RestAccessDeniedHandler restAccessDeniedHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
        .exceptionHandling(exceptionConfig -> exceptionConfig.authenticationEntryPoint(
            restAuthenticationEntryPoint).accessDeniedHandler(restAccessDeniedHandler));

    return http.build();
  }

}
