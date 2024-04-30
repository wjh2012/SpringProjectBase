package com.ggomg.project.base.config.security;

import com.ggomg.project.base.config.security.exceptionHandling.RestAccessDeniedHandler;
import com.ggomg.project.base.config.security.exceptionHandling.RestAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

  private final RestAuthenticationEntryPoint restAuthenticationEntryPoint;
  private final RestAccessDeniedHandler restAccessDeniedHandler;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(Customizer.withDefaults())
        .authorizeHttpRequests(
            authorizeRequest -> authorizeRequest
                .requestMatchers("/health").permitAll()
                .requestMatchers("/login").permitAll()
                .anyRequest().authenticated())
        .exceptionHandling(
            exceptionConfig -> exceptionConfig.authenticationEntryPoint(
                    restAuthenticationEntryPoint) // 미인증 401
                .accessDeniedHandler(restAccessDeniedHandler)) // 권한 부족 403
        .cors(Customizer.withDefaults());
    return http.build();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    config.addAllowedOrigin("http://localhost:3000"); // 허용할 출처
    config.setAllowCredentials(true); // 쿠키 인증 요청 허용
    config.setAllowPrivateNetwork(true); // PNA(private network access) 허용
    config.setMaxAge(3000L); // 원하는 시간만큼 pre-flight 리퀘스트를 캐싱
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
