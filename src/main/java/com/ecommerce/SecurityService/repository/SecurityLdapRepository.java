package com.ecommerce.SecurityService.repository;

import com.ecommerce.SecurityService.repository.entity.LdapUser;
import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecurityLdapRepository extends LdapRepository<LdapUser> {

    Optional<LdapUser> findByUsername(String name);
}