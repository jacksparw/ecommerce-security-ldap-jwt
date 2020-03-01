package com.ecommerce.SecurityService.dto;

import lombok.Data;

import java.io.Serializable;

@Data
public class JwtAuthenticationResponse implements Serializable {

    private static final long serialVersionUID = 1250166508152483573L;

    private final String token;
}
