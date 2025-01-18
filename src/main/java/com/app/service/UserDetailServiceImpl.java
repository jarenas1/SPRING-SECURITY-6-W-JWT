package com.app.service;

import com.app.controller.dto.AuthCreateUser;
import com.app.controller.dto.AuthLoginRequest;
import com.app.controller.dto.AuthResponse;
import com.app.persistence.entity.RoleEntity;
import com.app.persistence.entity.UserEntity;
import com.app.persistence.repository.RoleRepository;
import com.app.persistence.repository.UserRepository;
import com.app.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findUserEntityByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("El usuario " + username + " no existe."));

        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();

        userEntity.getRoles()
                .forEach(role -> authorityList.add(new SimpleGrantedAuthority("ROLE_".concat(role.getRoleEnum().name()))));

        userEntity.getRoles().stream()
                .flatMap(role -> role.getPermissionList().stream())
                .forEach(permission -> authorityList.add(new SimpleGrantedAuthority(permission.getName())));


        return new User(userEntity.getUsername(),
                userEntity.getPassword(),
                userEntity.isEnabled(),
                userEntity.isAccountNoExpired(),
                userEntity.isCredentialNoExpired(),
                userEntity.isAccountNoLocked(),
                authorityList);
    }

    //Metodo para ver si el usuario existe y sus credenciales son correctas
    public Authentication authenticate(String username, String password){
        //Buscamos al usuario con el metodo de arriba
        UserDetails userDetails = this.loadUserByUsername(username);


        //Verificamos si el usuario es nulo
        if (userDetails == null){
            throw new UsernameNotFoundException("El usuario " + username + " no existe.");
        }
        //Verificar que las contraseñas hagan match, para estpo debimos inyectar el password encoder
        if (!passwordEncoder.matches(password, userDetails.getPassword())){
            throw new BadCredentialsException("password mala");
        }
        //devolvemos un usuario autenticado
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    //METODO PARA LOGUEAR UN USUARIO
    public AuthResponse loginUser(AuthLoginRequest authLoginRequest){
        //obtenemos los datos del request
        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        //creamos un objeto de autenticacion
        Authentication authentication = this.authenticate(username,password);

        //seteamos la autenticacion en el contexto
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //creamos el token por medio del util que creamos, TOCA INYECTARLO
        String token = jwtUtils.createToken(authentication);

        //devolvemos la respuesta dto que creamos
        AuthResponse authResponse = new AuthResponse(username, "user authenticated", token, true);

        return authResponse;
    }

    //metodo para crear un usuario
    public AuthResponse createUser(AuthCreateUser authCreateUser){
        String username = authCreateUser.username();
        String password = authCreateUser.password();
        //roles, debemos verificar que los roles que envien si existan por ende creamos un repositorio
        List<String> roles = authCreateUser.roleRequest().roleListName();

        //Traemos los roles que esten en la base de datos y coincidan con el name de la lista
        Set<RoleEntity> roleEntitySet = roleRepository.findRoleEntitiesByRoleEnumIn(roles).stream()
                .collect(Collectors.toSet()); //pasamos a set la list

        //verificamos que los roles no sean vacios
        if (roleEntitySet.isEmpty()){
            throw new BadCredentialsException("the roles dont exist in the database");
        }

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password(passwordEncoder.encode(password)) //Hasheamos
                .roles(roleEntitySet)
                .build();

        UserEntity userCreated = userRepository.save(userEntity); //guardo

        //SI NO DESEO AUTENTICAR EL USUARIO SIMPOLEMENTE DEVUELVO EL USUAIO CREADO Y YA, SI DESEAMOS AUTENTICAS SEGUIMOS}

        //Podemos crear de nuevo un usuario de security y todo eso, o sumplemente pasamois las credenciales al metodo anterior

        AuthResponse userLoged = loginUser(new AuthLoginRequest(username, password));

        return new AuthResponse(userCreated.getUsername(), "user created", userLoged.token(), true);
    }
}
