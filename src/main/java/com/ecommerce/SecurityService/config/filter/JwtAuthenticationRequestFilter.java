package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.config.entryPoint.JwtAuthenticationEntryPoint;
import com.ecommerce.SecurityService.dto.JwtAuthenticationRequest;
import com.ecommerce.SecurityService.util.SecurityURLSettings;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

public class JwtAuthenticationRequestFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final SecurityURLSettings securityURLSettings;
    private final JwtAuthenticationEntryPoint authenticationEntryPoint;

    public JwtAuthenticationRequestFilter(AuthenticationManager authenticationManager, SecurityURLSettings securityURLSettings, JwtAuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationManager = authenticationManager;
        this.securityURLSettings = securityURLSettings;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        if (!request.getServletPath().equalsIgnoreCase(securityURLSettings.getAuthenticationPath())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            UsernamePasswordAuthenticationToken authRequest = convert(request);

            if (authRequest == null) {
                chain.doFilter(request, response);
                return;
            }

            Authentication authResult = this.authenticationManager
                    .authenticate(authRequest);

            SecurityContextHolder.getContext().setAuthentication(authResult);

        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();

            this.authenticationEntryPoint.commence(request, response, failed);

            return;
        }

        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {

        StringBuffer jb = new StringBuffer();
        String line;
        try {

            BufferedReader reader = request.getReader();
            while ((line = reader.readLine()) != null)
                jb.append(line);

            ObjectMapper mapper = new ObjectMapper();

            JwtAuthenticationRequest authenticationRequest = mapper.readValue(jb.toString(), JwtAuthenticationRequest.class);

            if(authenticationRequest != null
                    && !StringUtils.isEmpty(authenticationRequest.getUsername())
                    && !StringUtils.isEmpty(authenticationRequest.getPassword())){
                return new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword());
            }

        } catch (Exception e) {
            return null;
        }

        return null;
    }
}
