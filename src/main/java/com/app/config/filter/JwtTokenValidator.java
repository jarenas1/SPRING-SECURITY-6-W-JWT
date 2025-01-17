package com.app.config.filter;

import com.app.utils.JwtUtils;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

//la clase que extiene quiere decir que cada request se debe ejecutar este filtro!!
public class JwtTokenValidator extends OncePerRequestFilter {

    //inyectamos esto por medio de constructor ya que el autowired solo sirve para inyectar beans
    private JwtUtils jwtUtils;

    public JwtTokenValidator(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override //AÑADIMOS A LOS ATRIBUTOS EL @NonNull de java lang
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        //En el request debe vebir el header con el token, por ende lo extraemos
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION); //se importa de spring

        //Validamos si viene un token
        if (jwtToken != null){
            //ELIMINAREMOS EL BAREER QUE VIENE EN LA CABECERA PARA TENER SOLO EL TOKEN
            jwtToken = jwtToken.substring(7); //se eliminan los 7 primeros caracteres que componen barer

            //validamos el token por medio de los metodos creados anteriormente en util
            DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken);

            //extraemos el usuario y los permisos por medio de los metodos
            String username = jwtUtils.extractUsername(decodedJWT);
            String stringAuthorities = jwtUtils.getSpecificClamin(decodedJWT, "authorities").asString(); //PASO A STRING

            //SETEAMOS EL USUARIO CON SUS PERMISOS EN EL SECURITY CONTEXT HOLDER

            //EXTRAEMOS LOS PERMISOS Y LOS PASAMOS A CUALQUIER COSA QUE EXTIENDA de GrathedAuthorities
            //usaremos un metodo que ya nos provee el frameork para esto
            Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities);

            //extraemos el contexto de spring security
            SecurityContext securityContext = org.springframework.security.core.context.SecurityContextHolder.getContext();

            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);

            //SETEAMOS AUTENTICACION
            securityContext.setAuthentication(authentication);
            //seteamos de nuevo el context
            SecurityContextHolder.setContext(securityContext);
        }
        //Si es nulo, CONTINUA CON EL SIGUIENTE FILTRO:
        filterChain.doFilter(request, response);
    }
}
