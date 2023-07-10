package com.springsecurity.demo.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthUser implements Serializable {

    private static final long SERIAL_VERSION_UID = 1L;

    private String username;

    private String role;

}
