package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.redis.IRedisService;
import com.ecommerce.SecurityService.repository.SecurityLdapRoleRepository;
import com.ecommerce.SecurityService.repository.SecurityLdapUserRepository;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.repository.entity.LdapRole;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import com.ecommerce.SecurityService.util.SecurityURLSettings;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final String tokenHeader;
    private final SecurityLdapUserRepository ldapUserRepository;
    private final SecurityLdapRoleRepository ldapRoleRepository;
    private final IRedisService redisService;
    private final SecurityURLSettings securityURLSettings;

    public JwtAuthorizationTokenFilter(JwtTokenUtil jwtTokenUtil, String tokenHeader, SecurityLdapUserRepository ldapUserRepository, SecurityLdapRoleRepository ldapRoleRepository, IRedisService redisService, SecurityURLSettings securityURLSettings) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenHeader = tokenHeader;
        this.ldapUserRepository = ldapUserRepository;
        this.ldapRoleRepository = ldapRoleRepository;
        this.redisService = redisService;
        this.securityURLSettings = securityURLSettings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        if (request.getServletPath().equalsIgnoreCase(securityURLSettings.getAuthenticationPath())){
            chain.doFilter(request, response);
            return;
        }

        final String requestHeader = request.getHeader(tokenHeader);

        String username = null;
        String authToken = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            authToken = requestHeader.substring(7);

            if(redisService.searchKey(authToken)) {
                try {
                    username = jwtTokenUtil.getUsernameFromToken(authToken);
                } catch (IllegalArgumentException e) {
                    logger.error("an error occurred during getting username from token", e);
                } catch (ExpiredJwtException e) {
                    logger.warn("the token is expired and not valid anymore", e);
                } catch (SignatureException e) {
                    logger.warn("Invalid Token", e);
                }
            }
        } else {
            log.warn("couldn't find bearer string, will ignore the header");
        }

        log.debug("checking authentication for user '{}'", username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.debug("security context was null, so authorizing user");

            JwtUser userDetails = ldapUserRepository.findByUsername(username).get();

            List<LdapRole> roleList = ldapRoleRepository.findAllByMembersContains(userDetails.getDn().toString());

            userDetails.setAuthorities(roleList.stream()
                    .map(role -> role.getName())
                    .map(roleName -> new SimpleGrantedAuthority(roleName))
                    .collect(Collectors.toList()));

            if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("authorized user '{}', setting security context", username);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
