package com.ecommerce.SecurityService.config;

import com.ecommerce.SecurityService.config.entryPoint.JwtAuthenticationEntryPoint;
import com.ecommerce.SecurityService.config.filter.VerifyLDAPUserFilter;
import com.ecommerce.SecurityService.repository.SecurityLdapRepository;
import com.ecommerce.SecurityService.repository.entity.LdapUser;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.ldap.repository.config.EnableLdapRepositories;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.util.Collection;
import java.util.Optional;

@Log4j2
@Configuration
@EnableWebSecurity
@EnableLdapRepositories(basePackages = "com.ecommerce.SecurityService.*")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthenticationEntryPoint authenticationEntryPoint;

    public SecurityConfig(JwtAuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Bean
    public UserDetailsContextMapper userDetailsContextMapper() {
        return new LdapUserDetailsMapper() {

            @Autowired
            private SecurityLdapRepository ldapRepository;

            @Override
            public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {

                Optional<LdapUser> ldapUser = ldapRepository.findByUsername(username);

                LdapUser userDetails = ldapUser
                        .orElseThrow(() -> new BadCredentialsException("Wrong username or password"));

                userDetails.setAuthorities(authorities);
                userDetails.setPassword(new String((byte[]) ctx.getObjectAttribute("userpassword")));

                return userDetails;
            }
        };
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //@formatter:off

        auth
           .ldapAuthentication()
           .userDnPatterns("uid={0},ou=people")
           .groupSearchBase("ou=groups")
           .contextSource()
                .url("ldap://127.0.0.1:8388/dc=springframework,dc=org")
            .and()
            .passwordCompare()
              .passwordEncoder(new BCryptPasswordEncoder())
              .passwordAttribute("userPassword")
            .and()
                .userDetailsContextMapper(userDetailsContextMapper());

        //@formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //@formatter:off

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .httpBasic()
                .and()
                   .authorizeRequests()
                   .mvcMatchers("/hello")
                   .authenticated();

        http
            .addFilterAfter(new VerifyLDAPUserFilter(authenticationEntryPoint), BasicAuthenticationFilter.class);


        //@formatter:on
    }
}
