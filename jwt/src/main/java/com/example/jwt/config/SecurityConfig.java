package com.example.jwt.config;

import com.example.jwt.filter.MyFilter3;
import com.example.jwt.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)// 세션을 사용하지 않겠다
                .and()
                .addFilter(corsFilter) // 모든 요청은 이 필터를 거친다. (@CrossOrigin은 인증 없는곳에만 사용가능/ 이거는 시큐리티 필터에 등록해서 인증 있는곳 가능)
                .formLogin().disable() // 폼로그인 사용 안함
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
