package com.edu.uptc.gateway.apigateway;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Value("${jwt.secret}")
    private String SECRET_KEY ;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .csrf().disable() // Deshabilitar CSRF en APIs REST
            .authorizeExchange(exchanges -> exchanges
                // 1. Permitir acceso libre al Login (para que puedan obtener el token)
                // Ajusta la ruta según cómo llega a tu gateway (ej: /login/** o /auth/**)
                .pathMatchers("/login/**", "/auth/**").permitAll()
                
                // 2. Permitir OPTIONS (necesario para que Angular/Frontend no falle por CORS)
                .pathMatchers(org.springframework.http.HttpMethod.OPTIONS).permitAll()

                // 3. Todo lo demás requiere autenticación
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtDecoder(jwtDecoder())) // Usamos nuestro decodificador personalizado
            );

        return http.build();
    }

    // Bean para decodificar el Token usando tu Clave Secreta Simétrica (HS256)
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        byte[] keyBytes = SECRET_KEY.getBytes();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusReactiveJwtDecoder.withSecretKey(secretKeySpec).build();
    }
}
