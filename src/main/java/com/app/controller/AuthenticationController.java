package com.app.controller;

import com.app.controller.dto.AuthLoginRequest;
import com.app.controller.dto.AuthResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

     //LOGIN, todas las entidades que se ven aca son dtos
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthLoginRequest userRequest){
        return ResponseEntity(this.loginUser(userRequest), HttpStatus.OK);
    }
}
