package com.ecommerce.SecurityService.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Log4j2
@RestController
public class TestController {

    @GetMapping(value = "/hello", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> helloTest(Principal principal) {

        if(principal instanceof Authentication){

            Authentication authentication = (Authentication) principal;

            log.info(authentication.getAuthorities());
            log.info(authentication.getCredentials());
        }

        log.info(principal.getClass().getName());
        log.info(principal.getName());

        Map<String, String> data = new HashMap<>();
        data.put("message", "Hello");

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(60, TimeUnit.SECONDS))
                .body(data);
    }

    @GetMapping(value = "/public", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> publicApi() {

        Map<String, String> data = new HashMap<>();
        data.put("message", "public api");

        return data;
    }
}
