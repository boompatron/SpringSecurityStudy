package com.example.springsecuritystudy.global.redis;

public interface CacheRepository<T> {

	void save(String id, T value);

	T get(String id);

	void delete(String id);
}
