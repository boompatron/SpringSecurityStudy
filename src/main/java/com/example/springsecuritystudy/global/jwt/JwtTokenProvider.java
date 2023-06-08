package com.example.springsecuritystudy.global.jwt;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.example.springsecuritystudy.global.property.JwtProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenProvider {

	private final SecretKey secretKey;

	private final String issuer;
	private final long ACCESS_TOKEN_EXPIRE;
	private final long REFRESH_TOKEN_EXPIRE;

	public JwtTokenProvider(JwtProperties properties) {
		this.issuer = properties.getIssuer();
		this.ACCESS_TOKEN_EXPIRE = properties.getAccessTokenExpireSeconds();
		this.REFRESH_TOKEN_EXPIRE = properties.getRefreshTokenExpireSeconds();
		this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.getSecretKey()));
	}

	// 유저 정보를 가지고 AccessToken, RefreshToken 을 생성
	public TokenInfo generateToken(Authentication authentication) {
		// 권한 가져오기
		String authorities = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		Date now = new Date();

		return TokenInfo.builder()
				.grantType("Bearer")
				.accessToken(getAccessToken(authentication, authorities, now))
				.refreshToken(getRefreshToken(now))
				.build();
	}

	// JWT 을 복호화해서 안에 있는 정보를 꺼내느 메소드
	public Authentication getAuthentication(String accessToken) {
		// 토큰 복호화
		Claims claims = parseClaims(accessToken);
		// log.info("claims subject id : {}", Long.parseLong(claims.getSubject()));

		if (claims.get("auth") == null)
			throw new RuntimeException("권한 정보가 없는 토큰입니다.");

		// Claim 에서 권한 정보 가져오기
		Collection<? extends GrantedAuthority> authorities =
				Arrays.stream(claims.get("auth").toString().split(","))
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

		// UserDetail 객체를 만들어서 Authentication 객체 리턴
		UserDetails principal = new User(claims.getSubject(), "", authorities);
		return new UsernamePasswordAuthenticationToken(principal, "", authorities);
	}

	// 토큰 정보를 검증하는 메소드
	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
			return true;
		} catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
			log.info("Invalid JWT Token", e);
		} catch (ExpiredJwtException e) {
			log.info("Expired JWT Token", e);
		} catch (UnsupportedJwtException e) {
			log.info("Unsupported JWT Token", e);
		} catch (IllegalArgumentException e) {
			log.info("JWT claims string is empty.", e);
		}
		return false;
	}

	private String getAccessToken(Authentication authentication, String authorities, Date now) {
		Date expireAt = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE);

		return Jwts.builder()
				.setSubject(authentication.getName())
				.claim("auth", authorities)
				.setExpiration(expireAt)
				.signWith(secretKey, SignatureAlgorithm.HS256)
				.compact();
	}

	private String getRefreshToken(Date now) {
		Date expireAt = new Date(now.getTime() + REFRESH_TOKEN_EXPIRE);

		return Jwts.builder()
				.setExpiration(expireAt)
				.signWith(secretKey, SignatureAlgorithm.HS256)
				.compact();
	}

	private Claims parseClaims(String accessToken) {

		try {
			return Jwts.parserBuilder()
					.setSigningKey(secretKey)
					.build()
					.parseClaimsJws(accessToken)
					.getBody();
		} catch (ExpiredJwtException e) {
			return e.getClaims();
		}
	}
}
