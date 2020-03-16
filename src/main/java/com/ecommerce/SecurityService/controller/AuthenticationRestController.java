package com.ecommerce.SecurityService.controller;

import com.ecommerce.SecurityService.dto.JwtAuthenticationResponse;
import com.ecommerce.SecurityService.redis.IRedisService;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
public class AuthenticationRestController {

    private final JwtTokenUtil jwtTokenUtil;
    private final IRedisService redisService;

    @Value("${jwt.expiration.minutes:10}")
    private int expiration;

    public AuthenticationRestController(JwtTokenUtil jwtTokenUtil, IRedisService redisService) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.redisService = redisService;
    }

    @RequestMapping(value = "${jwt.route.authentication.authenticationPath}", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(Authentication authentication) {

        return ResponseEntity.ok(createJwtAuthenticationResponse(authentication));
    }

    @RequestMapping(value = "${jwt.route.authentication.refreshPath}", method = RequestMethod.POST)
    public ResponseEntity<?> refreshAuthenticationToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String refreshToken, Authentication authentication) {
        JwtUser user = (JwtUser) authentication.getPrincipal();
        final String token = refreshToken.substring(7);

        redisService.deleteKey(token);

        if (jwtTokenUtil.canTokenBeRefreshed(token, new Date(Long.parseLong(user.getLastPasswordResetDate())))) {
            return ResponseEntity.ok(createJwtAuthenticationResponse(authentication));
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }

    private JwtAuthenticationResponse createJwtAuthenticationResponse(Authentication authentication) {
        String authToken = jwtTokenUtil.generateAuthToken((UserDetails) authentication.getPrincipal());
        redisService.addKey(authToken, expiration);

        String refreshToken = jwtTokenUtil.generateRefreshToken((UserDetails) authentication.getPrincipal());
        redisService.addKey(refreshToken, 3 * expiration);

        return new JwtAuthenticationResponse(authToken, refreshToken);
    }

    @RequestMapping(value = "${jwt.route.authentication.invalidatePath}", method = RequestMethod.POST)
    public ResponseEntity<?> invalidateToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authToken) {
        redisService.deleteKey(authToken.substring(7));

        return ResponseEntity.ok().body(null);
    }
}
