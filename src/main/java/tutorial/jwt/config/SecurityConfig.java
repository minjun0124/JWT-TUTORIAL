package tutorial.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import tutorial.jwt.jwt.JwtAccessDeniedHandler;
import tutorial.jwt.jwt.JwtAuthenticationEntryPoint;
import tutorial.jwt.jwt.JwtSecurityConfig;
import tutorial.jwt.jwt.TokenProvider;

// 기본적인 Web 보안을 활성화
// 추가적으로 WebSecurityConfigurer 를 implements 하거나
// WebSucurityAdapter 를 extends 하는 방법이 있다.
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //@PreAuthorize 어노테이션을 메소드단위로 추가하기 위해서 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//    /**
//     * h2-console 하위 모든 요청들과 파비콘 관련 요청은 SpringSecurity 로직을 수행하지 않도록
//     */
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web
//                .ignoring()
//                .antMatchers(
//                        "/h2-console/**"
//                        , "/favicon.ico"
//                );
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()                                // HttpServletRequest 를 사용하는 요청들에 대한 접근제한을 설정하겠다.
//                .antMatchers("/api/hello").permitAll()   // "/api/hello" 에 대한 접근은 인증없이 접근을 허용하겠다.
//                .anyRequest().authenticated();                      // 그 외 나머지는 인증 정보가 필요하다.
//    }

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    /**
     * @param tokenProvider
     * @param jwtAuthenticationEntryPoint
     * @param jwtAccessDeniedHandler      위 클래스를 생성자 주입
     */
    public SecurityConfig(
            TokenProvider tokenProvider,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    /**
     * password encoder 로는 BCryptPasswordEncoder 를 사용
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * h2-console 하위 모든 요청들과 파비콘 관련 요청은 SpringSecurity 로직을 수행하지 않도록
     */
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(
                        "/h2-console/**"
                        , "/favicon.ico"
                        , "/error"
                );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
                .csrf().disable()

                // exception handling 처리에 내가 만든
                // authenticationEntryPoint(401), accessDeniedHandler(403) 를 추가해준다.
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // permitAll() - 토큰이 없는 상태에서 요청이 들어오는 Request 에 대해서 permit all 설정
                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                // JwtFilter 를 addFilterBefore 로 등록했던 JwtSecurityConfig 클래스를 적용
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}

