package com.example.springsecuritystudy.global.redis;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class RedisRepository<T> implements CacheRepository<T>{

	private final RedisTemplate<String, T> redisTemplate;

	@Override
	public void save(String key, T value) {
		ValueOperations<String, T> ops = redisTemplate.opsForValue();
		ops.set(key, value);
		redisTemplate.expire(key, 600L, TimeUnit.SECONDS);
	}

	@Override
	public T get(String key) {
		ValueOperations<String, T> ops = redisTemplate.opsForValue();
		T value = ops.get(key);
		return Objects.isNull(value) ? null : value;
	}

	@Override
	public void delete(String key) {
		ValueOperations<String, T> ops = redisTemplate.opsForValue();
		redisTemplate.delete(key);
	}
}
