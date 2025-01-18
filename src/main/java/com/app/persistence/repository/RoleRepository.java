package com.app.persistence.repository;

import com.app.persistence.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    //Buscara los roles que esten en la lista y los devolvera
    List<RoleEntity> findRoleEntitiesByRoleEnumIn(List<String> roleNames);
}
