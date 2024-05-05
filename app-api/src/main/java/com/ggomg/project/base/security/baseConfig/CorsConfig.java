package com.ggomg.project.base.security.baseConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

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
