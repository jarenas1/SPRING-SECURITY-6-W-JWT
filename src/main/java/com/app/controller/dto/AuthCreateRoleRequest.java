package com.app.controller.dto;

import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated //evita que pongamos @Valid en el controlador, validando aca en esta clase
//RECIBIUREMOS UNA LISTA"!! DE ROLES  MAX DE ROLES 3
public record AuthCreateRoleRequest(@Size(max = 3, message = "the user cannot have more than 3 roles") List<String> roleListName) {
}
