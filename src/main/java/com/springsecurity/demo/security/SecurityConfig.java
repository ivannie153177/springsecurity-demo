package com.springsecurity.demo.security;

import com.springsecurity.demo.model.IgnoredUrlsProperties;
import com.springsecurity.demo.security.filter.DemoAuthenticationFilter;
import com.springsecurity.demo.security.handler.CustomAccessDeniedHandler;
import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

    @Resource
    private IgnoredUrlsProperties ignoredUrlsProperties;

    @Resource
    private CorsConfigurationSource corsConfigurationSource;

    @Resource
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Resource
    private AuthenticationManager authenticationManager;

    @Bean
    @Primary
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        for (String url : ignoredUrlsProperties.getUrls()) {
            http.authorizeHttpRequests().requestMatchers(url).permitAll();
        }
        http.authorizeHttpRequests()
                .and()
                .headers().frameOptions().disable()
                .and()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and()
                .cors().configurationSource(corsConfigurationSource).and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler)
                .and()
                .addFilter(new DemoAuthenticationFilter(authenticationManager));
        return http.build();
    }

}
