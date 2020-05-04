package com.ecommerce.SecurityService.config.filter;

import com.ecommerce.SecurityService.repository.SecurityLdapRoleRepository;
import com.ecommerce.SecurityService.repository.SecurityLdapUserRepository;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.repository.entity.LdapRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthUtil {

    static JwtUser createJwtUser(String username, SecurityLdapUserRepository ldapUserRepository, SecurityLdapRoleRepository ldapRoleRepository) {
        JwtUser userDetails = ldapUserRepository.findByUsername(username).get();

        List<LdapRole> roleList = ldapRoleRepository.findAllByMembersEquals(userDetails.getDn().toString());

        userDetails.setAuthorities(roleList.stream()
                .map(role -> role.getName())
                .map(roleName -> new SimpleGrantedAuthority(roleName))
                .collect(Collectors.toList()));
        return userDetails;
    }

    static void addAuthenticationInSecurityContext(HttpServletRequest request, String username, JwtUser userDetails) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
