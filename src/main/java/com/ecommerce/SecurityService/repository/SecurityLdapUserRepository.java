package com.ecommerce.SecurityService.repository;

import com.ecommerce.SecurityService.repository.entity.JwtUser;
import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecurityLdapUserRepository extends LdapRepository<JwtUser> {

    Optional<JwtUser> findByUsername(String name);
}