package com.swiftmart.usermgmtservice.controllers;

import com.swiftmart.usermgmtservice.dtos.SignUpRequestDTO;
import com.swiftmart.usermgmtservice.dtos.UserDTO;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController//means this class will handle HTTP requests and return responses in a RESTful manner
// @RequestMapping("/api/auth")//base URL path for all endpoints in this controller
@RequestMapping("/users")
public class UserController {

    //public void signup(String name, String email, String password){
    //public User signup(SignUpRequestDTO signUpRequestDTO) {
    //public UserDTO signup(SignUpRequestDTO signUpRequestDTO) {

    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signup(@RequestBody SignUpRequestDTO signUpRequestDTO) {
        return null;
    }

    @PostMapping("/login")//Note:Login should be post as it will generate a token.So it will return a TokenDTO.
    //public void login(String email, String pas){
    public ResponseEntity<String> login(@RequestBody SignUpRequestDTO signUpRequestDTO) {
        return null;

    }
    public void validateToken(){

    }


}
