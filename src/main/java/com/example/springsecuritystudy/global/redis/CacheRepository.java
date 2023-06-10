package com.example.springsecuritystudy.global.redis;

public interface CacheRepository<T> {

	public void save(String id, T value);

	public T get(String id);

	public void delete(String id);
}
