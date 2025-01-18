package com.app.controller.dto;

//Características principales de un record:
//Inmutabilidad: Los campos de un record son automáticamente declarados como final y no pueden modificarse después de la creación.
//Concisión: Permite declarar clases con menos código, evitando la necesidad de escribir manualmente constructores, getters, equals(), hashCode(), y toString().
//Uso típico: Son útiles para representar DTOs (Data Transfer Objects) o clases que solo contienen datos.

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({"username", "message", "token", "status"}) //ORDEN EN EL QUE SE MOSTRARA EL JSON
public record AuthResponse(String username, String message, String token, boolean status) {
}
