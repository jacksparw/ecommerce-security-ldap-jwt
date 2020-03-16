package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.redis.IRedisService;
import com.ecommerce.SecurityService.repository.SecurityLdapRoleRepository;
import com.ecommerce.SecurityService.repository.SecurityLdapUserRepository;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import com.ecommerce.SecurityService.util.SecurityURLSettings;
import com.ecommerce.SecurityService.util.TokenType;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.ecommerce.SecurityService.config.filter.JWTAuthUtil.addAuthenticationInSecurityContext;
import static com.ecommerce.SecurityService.config.filter.JWTAuthUtil.createJwtUser;

@Log4j2
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final String tokenHeader;
    private final SecurityLdapUserRepository ldapUserRepository;
    private final SecurityLdapRoleRepository ldapRoleRepository;
    private final IRedisService redisService;
    private final SecurityURLSettings securityURLSettings;

    public JwtRefreshTokenFilter(JwtTokenUtil jwtTokenUtil, String tokenHeader, SecurityLdapUserRepository ldapUserRepository, SecurityLdapRoleRepository ldapRoleRepository, IRedisService redisService, SecurityURLSettings securityURLSettings) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenHeader = tokenHeader;
        this.ldapUserRepository = ldapUserRepository;
        this.ldapRoleRepository = ldapRoleRepository;
        this.redisService = redisService;
        this.securityURLSettings = securityURLSettings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        if (request.getServletPath().equalsIgnoreCase(securityURLSettings.getRefreshPath())) {
            final String requestHeader = request.getHeader(tokenHeader);

            String username = null;
            String refreshToken = null;
            if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
                refreshToken = requestHeader.substring(7);

                if (redisService.searchKey(refreshToken)) {
                    try {
                        if (jwtTokenUtil.getTokenType(refreshToken).equalsIgnoreCase(TokenType.REFRESH.name())) {
                            username = jwtTokenUtil.getUsernameFromToken(refreshToken);
                        }
                    } catch (IllegalArgumentException | ExpiredJwtException | SignatureException e) {
                        logger.error("an error occurred during getting username from token", e);
                    }
                }
            } else {
                log.warn("couldn't find bearer string, will ignore the header");
            }

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                logger.debug("security context was null, so authorizing user");

                JwtUser userDetails = createJwtUser(username, ldapUserRepository, ldapRoleRepository);

                if (jwtTokenUtil.validateToken(refreshToken, userDetails)) {
                    addAuthenticationInSecurityContext(request, username, userDetails);
                }
            }
        }

        chain.doFilter(request, response);
    }
}
