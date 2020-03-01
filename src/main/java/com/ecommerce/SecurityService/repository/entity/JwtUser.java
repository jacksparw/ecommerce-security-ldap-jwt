package com.ecommerce.SecurityService.repository.entity;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;
import org.springframework.ldap.odm.annotations.Transient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.naming.Name;
import java.util.Collection;

@Data
@NoArgsConstructor
@Entry(base="ou=people,dc=springframework,dc=org", objectClasses = {
        "top", "inetOrgPerson", "person", "organizationalPerson"})
public class JwtUser implements UserDetails {

    private static final long serialVersionUID = 1L;

    private @Id Name dn;
    private @Attribute(name = "fn") String firstName;
    private @Attribute(name = "sn") String lastName;
    private @Attribute(name = "mail") String email;
    private @Attribute(name = "lastPasswordResetDate") String lastPasswordResetDate;
    private @Attribute(name = "uid") String username;
    private @Attribute(name = "enabled") boolean enabled;
    private @Transient Collection<? extends GrantedAuthority> authorities;
    private @Transient String password;

    @Override
    public boolean isAccountNonExpired() {
        return enabled;
    }

    @Override
    public boolean isAccountNonLocked() {
        return enabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return enabled;
    }
}