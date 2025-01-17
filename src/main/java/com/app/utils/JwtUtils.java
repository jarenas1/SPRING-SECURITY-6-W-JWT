package com.app.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${security.jwt.private}")
    private String jwtPrivateKey;

    @Value("${security.jwt.user.generator]")
    private String jwtUserGenerator;

    //authentication es como del contexto de autenticacion y trae datos del usuario que intenta acceder
    public String createToken(Authentication authentication){
        //metodo de encriptacion
        Algorithm algorithm = Algorithm.HMAC256(jwtPrivateKey);
        //Treamos el usuario que esta intentando autenticarse
        String username = authentication.getPrincipal().toString();
        //OBTENEMOS AUTORIZACIONES Y PERMISOS, debemos pasar de una coleccion a un string separado por , asi:
        String authorities = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(",")); //DEVUELVE TODO ASI ADMIN, USER, DEV}

        //generamos el token
        String jwtToken = JWT.create()
                .withIssuer(this.jwtUserGenerator) //Usuario declarado al inicio
                .withSubject(username) //Usuario que esta tratando de autenticarse
                .withClaim("authorities", authorities) //permisops y roles como un claim
                .withIssuedAt(new Date()) //Fecha de generacion del token
                .withExpiresAt(new Date(System.currentTimeMillis()+1800000)) //expiracion en ms, local + 18k
                .withJWTId(UUID.randomUUID().toString()) //ID PARA EL TOKEN
                .withNotBefore(new Date(System.currentTimeMillis())) //Tiempo despues de la generacion en el que el token sera valido, ej, se genera a la una pero sera valido 2 horas depspues, debe ser en MS
                .sign(algorithm); //Pasamos el algoritmo de encriptacion con la firma q creamos arriba
        return jwtToken;
    }
}
