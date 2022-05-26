package com.crud.springmaven.Controller;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.crud.springmaven.DAO.IUsuarioDAO;
import com.crud.springmaven.DTO.Usuario;

@RestController
@CrossOrigin(origins = "*", methods= {RequestMethod.GET,RequestMethod.POST,RequestMethod.PUT,RequestMethod.DELETE})
public class UsuarioController {

	private IUsuarioDAO iUsuarioDAO;

	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public UsuarioController(IUsuarioDAO iUsuarioDAO, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.iUsuarioDAO = iUsuarioDAO;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}
	
	
	@GetMapping("/response-entity-builder-with-http-headers")
	public ResponseEntity<String> usingResponseEntityBuilderAndHttpHeaders() {
	    HttpHeaders responseHeaders = new HttpHeaders();
	    responseHeaders.set("Baeldung-Example-Header", 
	      "Value-ResponseEntityBuilderWithHttpHeaders");

	    return ResponseEntity.ok()
	      .headers(responseHeaders)
	      .body("Response with header using ResponseEntity");
	}
	
	@PostMapping("/users/")
	public Usuario saveUsuario(@RequestBody Usuario user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		iUsuarioDAO.save(user);
		return user;
	}

	@GetMapping("/users/")
	public List<Usuario> getAllUsuarios() {
		return iUsuarioDAO.findAll();
	}

	@GetMapping("/users/{username}")
	public Usuario getUsuario(@PathVariable String username) {
		return iUsuarioDAO.findByUsername(username);
	}
	
	@DeleteMapping("/users/{id}")
	public String eliminarUser(@PathVariable(name="id")long id) {
		iUsuarioDAO.deleteById(id);
		return "User deleted.";
	}
}