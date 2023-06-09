package com.example.springsecuritystudy.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.springsecuritystudy.global.jwt.JwtAuthenticationFilter;
import com.example.springsecuritystudy.global.jwt.JwtTokenProvider;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	// TODO 경로 설정 및 추가 수정

	private final JwtTokenProvider jwtTokenProvider;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				// rest api 이므로 basic auth, csrf 보안을 안쓰겠다.
				.csrf().disable()
				.httpBasic().disable()
				.formLogin().disable()
				.rememberMe().disable()
				.logout().disable()
				.requestCache().disable()
				.headers().disable()
				// jwt 를 사용하므로 session 은 사용하지 않겠다
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				// 각 사이트에 대해 권한을 조정한다
				.authorizeRequests()
				// 이 사이트는 어떤 요청이 와도 그냥 들어와도 된다
				.antMatchers("/members/login", "/members/signUp", "/members/reissue")
				.permitAll()
				// 이 사이트는 USER 권한이 있어야 한다
				.antMatchers("/members/test").hasRole("USER")
				// 이 외 모든 요청은 인증을 필요로 한다
				.anyRequest().authenticated()
				.and()
				// JWT을 통한 인증을 위해 직접 구현안 필터를 username 전에 사용하겠다
				.addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

}
