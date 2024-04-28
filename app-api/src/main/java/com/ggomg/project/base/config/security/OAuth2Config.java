package com.ggomg.project.base.config.security;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class OAuth2Config {

    //	프로토콜 끝점을 위한 Spring Security 필터 체인
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
//        throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//            .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
//        http
//            // Redirect to the login page when not authenticated from the
//            // authorization endpoint
//            .exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
//                new LoginUrlAuthenticationEntryPoint("/login"),
//                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
//            // Accept access tokens for User Info and/or Client Registration
//            .oauth2ResourceServer(
//                (resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));
//
//        return http.build();
//    }
//
//    // 인증을 위한 Spring Security 필터 체인
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
//            // Form login handles the redirect to the login page from the
//            // authorization server filter chain
//            .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
//
//    //	UserDetailsService인증할 사용자를 검색하기 위한 인스턴스
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder().username("user")
//            .password("password").roles("USER").build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    // 클라이언트 관리를 위한 RegisteredClientRepository 인스턴스
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//            .clientId("oidc-client").clientSecret("{noop}secret")
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//            .postLogoutRedirectUri("http://127.0.0.1:8080/").scope(OidcScopes.OPENID)
//            .scope(OidcScopes.PROFILE)
//            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//            .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }
//
//    // 액세스 토큰 서명을 위한 JWKSource 인스턴스
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() {
//        KeyPair keyPair = generateRsaKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey)
//            .keyID(UUID.randomUUID().toString()).build();
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    // 위 항목 을 생성하는 데 사용된 시작 시 생성된 키가 있는 인스턴스
//    private static KeyPair generateRsaKey() {
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//            keyPairGenerator.initialize(2048);
//            keyPair = keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
//    }
//
//    // 서명된 액세스 토큰을 디코딩하기 위한 JwtDecoder 인스턴스
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    // AuthorizationServerSettingsSpring Authorization Server를 구성하기 위한 AuthorizationServerSettingsSpring 인스턴스
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }

}
