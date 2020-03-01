package com.ecommerce.SecurityService.repository.entity;

import lombok.Data;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;

import javax.naming.Name;
import java.util.List;

@Data
@Entry(objectClasses = {"groupOfUniqueNames", "top"}, base = "ou=groups,dc=springframework,dc=org")
public class LdapRole {

    @Id
    private Name dn;

    private @Attribute(name = "cn")
    String name;

    private @Attribute(name = "uniqueMember")
    List<String> members;

}