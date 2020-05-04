package com.ecommerce.SecurityService.config;

import com.ecommerce.SecurityService.config.entryPoint.JwtAuthenticationEntryPoint;
import com.ecommerce.SecurityService.config.filter.JwtAuthenticationRequestFilter;
import com.ecommerce.SecurityService.config.filter.JwtAuthorizationTokenFilter;
import com.ecommerce.SecurityService.config.filter.JwtRefreshTokenFilter;
import com.ecommerce.SecurityService.config.filter.VerifyLDAPUserFilter;
import com.ecommerce.SecurityService.redis.IRedisService;
import com.ecommerce.SecurityService.repository.SecurityLdapRoleRepository;
import com.ecommerce.SecurityService.repository.SecurityLdapUserRepository;
import com.ecommerce.SecurityService.repository.entity.JwtUser;
import com.ecommerce.SecurityService.util.JwtTokenUtil;
import com.ecommerce.SecurityService.util.SecurityURLSettings;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Optional;

@Log4j2
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    private final JwtTokenUtil jwtTokenUtil;
    private final SecurityLdapUserRepository ldapUserRepository;
    private final SecurityLdapRoleRepository ldapRoleRepository;
    private final IRedisService redisService;
    private final SecurityURLSettings securityURLSettings;

    //@formatter:off
    private @Value("${jwt.header}") String tokenHeader;
    private @Value("${ldap.url}") String ldapURL;
    private @Value("${ldap.partitionSuffix}") String ldapPartitionSuffix;
    private @Value("${ldap.userDnPattern}") String ldapUserDNPattern;
    private @Value("${ldap.groupSearchBase}") String ldapGroupSearchBase;
    private @Value("${ldap.passwordAttribute}") String ldapPasswordAttribute;
    //@formatter:on

    public SecurityConfig(JwtAuthenticationEntryPoint authenticationEntryPoint, JwtTokenUtil jwtTokenUtil, SecurityLdapUserRepository ldapUserRepository, SecurityLdapRoleRepository ldapRoleRepository, IRedisService redisService, SecurityURLSettings securityURLSettings) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwtTokenUtil = jwtTokenUtil;
        this.ldapUserRepository = ldapUserRepository;
        this.ldapRoleRepository = ldapRoleRepository;
        this.redisService = redisService;
        this.securityURLSettings = securityURLSettings;
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public UserDetailsContextMapper userDetailsContextMapper() {
        return new LdapUserDetailsMapper() {

            @Override
            public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {

                Optional<JwtUser> jwtUser = ldapUserRepository.findByUsername(username);

                JwtUser userDetails = jwtUser
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
           .userDnPatterns(ldapUserDNPattern)
           .groupSearchBase(ldapGroupSearchBase)
           .contextSource()
                .url(ldapURL+ldapPartitionSuffix)
            .and()
            .passwordCompare()
              .passwordEncoder(new BCryptPasswordEncoder())
              .passwordAttribute(ldapPasswordAttribute)
            .and()
                .userDetailsContextMapper(userDetailsContextMapper());

        //@formatter:on
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //@formatter:off

        http.csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                .and()
                   .authorizeRequests()
                   .mvcMatchers("/hello")
                        .hasAnyAuthority("developer", "admin")
                   .mvcMatchers(securityURLSettings.getAuthenticationPath(),
                                securityURLSettings.getRefreshPath(),
                                securityURLSettings.getInvalidatePath())
                        .authenticated()
                   .mvcMatchers("/public")
                        .permitAll();

        http.addFilterAt(new JwtAuthenticationRequestFilter(authenticationManager(),securityURLSettings, authenticationEntryPoint),
                    UsernamePasswordAuthenticationFilter.class)
            .addFilterAt(new JwtAuthorizationTokenFilter(jwtTokenUtil,tokenHeader, ldapUserRepository, ldapRoleRepository, redisService, securityURLSettings),
                    UsernamePasswordAuthenticationFilter.class)
            .addFilterAt(new JwtRefreshTokenFilter(jwtTokenUtil,tokenHeader, ldapUserRepository, ldapRoleRepository, redisService, securityURLSettings),
                UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(new VerifyLDAPUserFilter(authenticationEntryPoint), UsernamePasswordAuthenticationFilter.class);

        //@formatter:on
    }

    @Override
    public void configure(WebSecurity web) {
        // AuthenticationTokenFilter will ignore the below paths
        web
                // allow anonymous resource requests
                .ignoring()
                .antMatchers(
                        HttpMethod.GET,
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                );
    }
}
