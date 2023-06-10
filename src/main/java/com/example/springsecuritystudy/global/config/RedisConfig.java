package com.example.springsecuritystudy.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

import com.example.springsecuritystudy.global.property.RedisProperties;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class RedisConfig {

	private final RedisProperties redisProperties;

	@Bean
	public RedisConnectionFactory redisConnectionFactory(){
		return new LettuceConnectionFactory(redisProperties.getHost(), redisProperties.getPort());
	}

	// @Bean
	// public StringRedisTemplate stringRedisTemplate(){
	// 	StringRedisTemplate stringRedisTemplate = new StringRedisTemplate();
	// 	stringRedisTemplate.setConnectionFactory(redisConnectionFactory());
	// 	return stringRedisTemplate;
	// }

	@Bean
	public RedisTemplate<String, String> redisTemplate(){
		RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(redisConnectionFactory());
		return redisTemplate;
	}
}
