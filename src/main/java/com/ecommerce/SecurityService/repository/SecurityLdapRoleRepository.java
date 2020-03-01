package com.ecommerce.SecurityService.repository;

import com.ecommerce.SecurityService.repository.entity.LdapRole;
import com.ecommerce.SecurityService.repository.entity.LdapUser;
import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SecurityLdapRoleRepository extends LdapRepository<LdapRole> {

    List<LdapRole> findAllByMembersContains(String member);
}