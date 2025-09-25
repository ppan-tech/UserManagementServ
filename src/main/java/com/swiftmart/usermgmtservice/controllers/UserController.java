package com.swiftmart.usermgmtservice.controllers;

import com.swiftmart.usermgmtservice.dtos.LoginRequestDTO;
import com.swiftmart.usermgmtservice.dtos.SignUpRequestDTO;
import com.swiftmart.usermgmtservice.dtos.TokenDTO;
import com.swiftmart.usermgmtservice.dtos.UserDTO;
import com.swiftmart.usermgmtservice.exceptions.PasswordMismatchException;
import com.swiftmart.usermgmtservice.models.Token;
import com.swiftmart.usermgmtservice.models.User;
import com.swiftmart.usermgmtservice.services.UserService;
import lombok.Getter;
import org.apache.coyote.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController//means this class will handle HTTP requests and return responses in a RESTful manner
// @RequestMapping("/api/auth")//base URL path for all endpoints in this controller
@RequestMapping("/users")
public class UserController {
    private UserService userService;
    //public void signup(String name, String email, String password){
    //public User signup(SignUpRequestDTO signUpRequestDTO) {
    //public UserDTO signup(SignUpRequestDTO signUpRequestDTO) {

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public UserDTO signup(@RequestBody SignUpRequestDTO signUpRequestDTO) {
        User user = userService.signup(signUpRequestDTO.getName(),
                signUpRequestDTO.getEmail(),
                signUpRequestDTO.getPassword());
        //Note:But we should not return the User entity directly as it may expose sensitive info like password.
        //Instead we should return a UserDTO which contains only the fields we want to expose.



        return UserDTO.from(user);//Note:This way it is implemented in FAANG companies.
        //return null;
    }

    @PostMapping("/login")//Note:Login should be post as it will generate a token.So it will return a TokenDTO.
    //public void login(String email, String pas){
    public TokenDTO login(@RequestBody LoginRequestDTO requestDTO) throws PasswordMismatchException {
       // return null;
        Token token = userService.login(
                requestDTO.getEmail(),
                requestDTO.getPassword()
        );

        return TokenDTO.from(token);
    }

    @GetMapping("/validate/{tokenValue}")
    public UserDTO validateToken(@PathVariable("tokenValue") String tokenValue) {
        return null;
    }
}
