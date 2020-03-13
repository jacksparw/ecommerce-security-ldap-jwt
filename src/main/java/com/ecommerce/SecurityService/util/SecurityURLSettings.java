package com.ecommerce.SecurityService.util;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties("jwt.route.authentication")
public class SecurityURLSettings {

    private String authenticationPath;
    private String refreshPath;
    private String invalidatePath;
}
