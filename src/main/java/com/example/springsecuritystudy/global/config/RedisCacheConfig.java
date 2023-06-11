package com.example.springsecuritystudy.global.config;

import java.time.Duration;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
@EnableCaching
public class RedisCacheConfig {

	@Bean
	public RedisCacheConfiguration redisCacheConfiguration(){
		return RedisCacheConfiguration.defaultCacheConfig()
				.entryTtl(Duration.ofSeconds(60)) // 1분간 지속
				.disableCachingNullValues(); // Null 은 value 로 안 받음
				// .serializeKeysWith(
				// 		RedisSerializationContext.SerializationPair.fromSerializer(
				// 				new StringRedisSerializer()
				// 		)
				// )
				// .serializeValuesWith(
				// 		RedisSerializationContext.SerializationPair.fromSerializer(
				// 				new GenericJackson2JsonRedisSerializer()
				// 		)
				// );
	}

	// @Bean
  //   public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
  //       return (builder) -> builder
  //               .withCacheConfiguration("cache1",
  //                       RedisCacheConfiguration.defaultCacheConfig()
  //                               .computePrefixWith(cacheName -> "prefix::" + cacheName + "::")
  //                               .entryTtl(Duration.ofSeconds(120))
  //                               .disableCachingNullValues()
  //                               .serializeKeysWith(
  //                                       RedisSerializationContext.SerializationPair.fromSerializer(new StringRedisSerializer())
  //                               )
  //                               .serializeValuesWith(
  //                                       RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer())
  //                               ))
  //               .withCacheConfiguration("cache2",
  //                       RedisCacheConfiguration.defaultCacheConfig()
  //                               .entryTtl(Duration.ofHours(2))
  //                               .disableCachingNullValues());
  //   }

}
