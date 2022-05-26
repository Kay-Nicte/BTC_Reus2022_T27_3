package com.crud.springmaven.DAO;

import org.springframework.data.jpa.repository.JpaRepository;
import com.crud.springmaven.DTO.Usuario;

public interface IUsuarioDAO extends JpaRepository<Usuario, Long> {

	Usuario findByUsername(String username);
}