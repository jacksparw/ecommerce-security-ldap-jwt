package com.ecommerce.SecurityService.controller;

import com.ecommerce.SecurityService.dto.JwtAuthenticationResponse;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@RestController
public class AuthenticationRestController {

    private final JwtTokenUtil jwtTokenUtil;
    @Value("${jwt.header}")
    private String tokenHeader;

    public AuthenticationRestController(JwtTokenUtil jwtTokenUtil) {
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @RequestMapping(value = "${jwt.route.authentication.path}", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(Authentication authentication) {

        return ResponseEntity.ok(new JwtAuthenticationResponse(
                jwtTokenUtil.generateToken((UserDetails) authentication.getPrincipal())
        ));
    }

    @RequestMapping(value = "${jwt.route.authentication.refresh}", method = RequestMethod.POST)
    public ResponseEntity<?> refreshAuthenticationToken(HttpServletRequest httpServletRequest, Authentication authentication) {
        JwtUser user = (JwtUser) authentication.getPrincipal();

        String authToken = httpServletRequest.getHeader(tokenHeader);
        final String token = authToken.substring(7);

        if (jwtTokenUtil.canTokenBeRefreshed(token, new Date(Long.parseLong(user.getLastPasswordResetDate())))) {
            String refreshedToken = jwtTokenUtil.refreshToken(token);
            return ResponseEntity.ok(new JwtAuthenticationResponse(refreshedToken));
        } else {
            return ResponseEntity.badRequest().body(null);
        }
    }
}
