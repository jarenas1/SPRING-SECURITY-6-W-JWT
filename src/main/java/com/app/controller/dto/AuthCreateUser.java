package com.app.controller.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

public record AuthCreateUser(
        @NotBlank String username,
        @NotBlank String password,
        //lOS ROLES AL SER UNA LISTA LOS PASAREMOS DESDE OTRO OBJETO
        @Valid AuthCreateRoleRequest roleRequest

) {
}
