package com.swiftmart.usermgmtservice.services;

import com.swiftmart.usermgmtservice.models.Token;
import com.swiftmart.usermgmtservice.models.User;
import com.swiftmart.usermgmtservice.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    public UserServiceImpl(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @Override
    public User signup(String name, String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isPresent()){
            return optionalUser.get();
        }
        //But if email is not present in DBthen create a new user and save it to DB.
        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setPassword(bCryptPasswordEncoder.encode(password));//Note:In real world app we should hash the password before saving.


        /*
        But we should not create password encoder object every time we need to encode a password.So we can create a bean
         of password encoder and inject it here.By Creating in ApplicationConfig.
         */
        //now save the user to DB
        user = userRepository.save(user);//input user will not have 'id' but output user will have.
        return user;
    }

    @Override
    public Token login(String email, String password) {
        return null;
    }

    @Override
    public User validateToken(String tokenValue) {
        return null;
    }
}
