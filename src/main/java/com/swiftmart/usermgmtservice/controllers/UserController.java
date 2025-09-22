package com.swiftmart.usermgmtservice.controllers;

import com.swiftmart.usermgmtservice.dtos.SignUpRequestDTO;
import com.swiftmart.usermgmtservice.dtos.UserDTO;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController//means this class will handle HTTP requests and return responses in a RESTful manner
// @RequestMapping("/api/auth")//base URL path for all endpoints in this controller

public class UserController {

    //public void signup(String name, String email, String password){
    //public User signup(SignUpRequestDTO signUpRequestDTO) {
    //public UserDTO signup(SignUpRequestDTO signUpRequestDTO) {
    public ResponseEntity<UserDTO> signup(SignUpRequestDTO signUpRequestDTO) {
        return null;
    }
    public void login(){

    }
    public void validateToken(){

    }


}
