package tutorial.jwt.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * No.3
 * TokenProvide, JwtFilter 를 SecurityConfig 에 적용할 때 사용할 JwtSecurityConfig 클래스 추가
 * 
 * SecurityConfigurerAdapter 를 extends 하고
 * TokenProvider 를 주입받아서 JwtFilter를 통해 Security 로직에 필터를 등록
 */
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenProvider tokenProvider;

    /**
     * TokenProvider 를 주입
     */
    public JwtSecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /**
     * JwtFilter를 통해 Security 로직에 필터를 등록
     */
    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
