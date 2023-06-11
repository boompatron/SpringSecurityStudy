package com.example.springsecuritystudy.global.redis;

import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.stereotype.Component;

import com.example.springsecuritystudy.global.jwt.TokenInfo;

import lombok.Getter;


@Getter
@Component
public class RedisTokenTemplate extends RedisRepository<TokenInfo>{


	public RedisTokenTemplate(RedisTemplate<String, TokenInfo> redisTemplate) {
		super(redisTemplate);
		super.redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());
	}

	public void setConnectionFactory(RedisConnectionFactory connectionFactory) {
		super.redisTemplate.setConnectionFactory(connectionFactory);
	}
}
