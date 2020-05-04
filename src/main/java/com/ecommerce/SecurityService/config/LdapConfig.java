package com.ecommerce.SecurityService.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.ldap.repository.config.EnableLdapRepositories;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

@Configuration
@EnableLdapRepositories(basePackages = "com.ecommerce.SecurityService.*")
public class LdapConfig {

    //@formatter:off
    private @Value("${ldap.url}") String ldapURL;
    private @Value("${ldap.partitionSuffix}") String ldapPartitionSuffix;
    private @Value("${ldap.principal}") String ldapPrincipal;
    private @Value("${ldap.password}") String ldapPassword;
    //@formatter:on

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapURL);
        contextSource.setBase(ldapPartitionSuffix);
        contextSource.setUserDn(ldapPrincipal);
        contextSource.setPassword(ldapPassword);
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }
}
