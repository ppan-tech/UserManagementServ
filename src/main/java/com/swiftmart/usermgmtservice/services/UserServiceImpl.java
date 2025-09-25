package com.swiftmart.usermgmtservice.services;

import com.swiftmart.usermgmtservice.exceptions.PasswordMismatchException;
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
    public Token login(String email, String password) throws PasswordMismatchException {
        //lets first get the user by email from DB
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()){
            //redirect to signup
            return null;
        }
        User user = optionalUser.get();
        if(!bCryptPasswordEncoder.matches(password, user.getPassword())){
            //password mismtach
            //we should throw an exception here.ie.PasswordMismatchException.
            throw new PasswordMismatchException("Invalid Password");
        }

        //SUCCESSFUL of login--FLOW:
        //if control reaches here, means login is successful.
        Token token = new Token();
        token.setUser(user);
        //generate a random token value and set it to token object.
        token.setTokenValue(java.util.UUID.randomUUID().toString());
        //set the expiry time of token to 1 hour from now.
        token.setExpiryTime(System.currentTimeMillis() + 3600 * 1000);//
        //Note:3600*1000 means 1 hour in milliseconds.
        return token;

        return null;
    }

    @Override
    public User validateToken(String tokenValue) {
        return null;
    }
}
