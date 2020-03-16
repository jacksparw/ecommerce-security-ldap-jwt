package com.ecommerce.SecurityService.redis;

import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import java.util.concurrent.TimeUnit;

@Service
public class RedisService implements IRedisService {

    private final StringRedisTemplate redisTemplate;

    public RedisService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean searchKey(String key) {
       return redisTemplate.hasKey(DigestUtils.md5DigestAsHex(key.getBytes()));
    }

    @Override
    public boolean addKey(String key, int expTimeInMinutes) {
        SetOperations setOperations = redisTemplate.opsForSet();
        setOperations.add(DigestUtils.md5DigestAsHex(key.getBytes()), "");

        return redisTemplate.expire(DigestUtils.md5DigestAsHex(key.getBytes()), expTimeInMinutes, TimeUnit.MINUTES);
    }

    @Override
    public boolean deleteKey(String key) {
        return redisTemplate.delete(DigestUtils.md5DigestAsHex(key.getBytes()));
    }
}
