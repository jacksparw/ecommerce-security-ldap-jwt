package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.config.JwtUser;
import com.ecommerce.SecurityService.repository.SecurityLdapRoleRepository;
import com.ecommerce.SecurityService.repository.SecurityLdapUserRepository;
import com.ecommerce.SecurityService.repository.entity.LdapRole;
import com.ecommerce.SecurityService.repository.entity.LdapUser;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import com.ecommerce.SecurityService.util.JwtUserFactory;
import io.jsonwebtoken.ExpiredJwtException;
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

    public JwtAuthorizationTokenFilter(JwtTokenUtil jwtTokenUtil, String tokenHeader, SecurityLdapUserRepository ldapUserRepository, SecurityLdapRoleRepository ldapRoleRepository) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenHeader = tokenHeader;
        this.ldapUserRepository = ldapUserRepository;
        this.ldapRoleRepository = ldapRoleRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        if (request.getServletPath().equalsIgnoreCase("/auth")){
            chain.doFilter(request, response);
            return;
        }

        final String requestHeader = request.getHeader(tokenHeader);

        String username = null;
        String authToken = null;
        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            authToken = requestHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(authToken);
            } catch (IllegalArgumentException e) {
                logger.error("an error occurred during getting username from token", e);
            } catch (ExpiredJwtException e) {
                logger.warn("the token is expired and not valid anymore", e);
            } catch (Exception e) {
                throw e;
            }
        } else {
            log.warn("couldn't find bearer string, will ignore the header");
        }

        log.debug("checking authentication for user '{}'", username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.debug("security context was null, so authorizing user");

            LdapUser userDetails = ldapUserRepository.findByUsername(username).get();

            List<LdapRole> roleList = ldapRoleRepository.findAllByMembersContains(userDetails.getDn().toString());

            userDetails.setAuthorities(roleList.stream()
                    .map(e -> e.getName())
                    .map(e -> new SimpleGrantedAuthority(e))
                    .collect(Collectors.toList()));

            JwtUser jwtUser = JwtUserFactory.create(userDetails);

            if (jwtTokenUtil.validateToken(authToken, jwtUser)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(jwtUser, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                log.info("authorized user '{}', setting security context", username);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
