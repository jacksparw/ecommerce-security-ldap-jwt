package com.ecommerce.SecurityService.redis;

import org.springframework.stereotype.Service;

@Service
public interface IRedisService {

    boolean searchKey(String key);

    boolean addKey(String key);

    boolean deleteKey(String key);
}
