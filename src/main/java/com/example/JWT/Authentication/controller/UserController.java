package com.example.JWT.Authentication.controller;

import com.example.JWT.Authentication.model.Product;
import com.example.JWT.Authentication.model.User;
import com.example.JWT.Authentication.repository.ProductRepository;
import com.example.JWT.Authentication.repository.UserRepository;
import com.example.JWT.Authentication.service.JwtUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class UserController {

    private UserRepository userRepository;

    @Autowired
    private JwtUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ProductRepository productRepository;

    public UserController(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @PostMapping("/api/v1/user")
    public String createUser(@RequestBody User user) {
        String password = user.getPassword();
        String encode = new BCryptPasswordEncoder().encode(password);
        user.setPassword(encode);
        userRepository.save(user);
        return "User saved Successfully";
    }

    @GetMapping("/api/v1/createtoken")
    public String createToken(@RequestParam("email") String email,@RequestParam("password") String password) {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        if(authenticate.isAuthenticated()){
            String token = jwtUtility.generateToken(email);
            return token;
        }
        return "UserName or Password is Incorrect";
    }

    @GetMapping("/api/v1/products")
    public List<Product> getProducts() {
        List<Product> products = productRepository.findAll();
        return products;
    }
}
