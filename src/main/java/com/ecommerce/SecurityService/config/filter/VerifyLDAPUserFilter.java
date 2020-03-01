package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.config.entryPoint.JwtAuthenticationEntryPoint;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class VerifyLDAPUserFilter extends OncePerRequestFilter {

    private final JwtAuthenticationEntryPoint authenticationEntryPoint;

    public VerifyLDAPUserFilter(JwtAuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        try {
            if (authentication != null && authentication.getPrincipal() != null) {
                if (!((JwtUser) authentication.getPrincipal()).isEnabled()) {
                    throw new DisabledException("Account Disabled");
                }
            }
        } catch (DisabledException ex) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, ex);
            return;
        }

        chain.doFilter(request, response);
    }
}
