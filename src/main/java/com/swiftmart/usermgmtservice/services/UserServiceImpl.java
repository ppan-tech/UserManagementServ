package com.swiftmart.usermgmtservice.services;

import com.swiftmart.usermgmtservice.exceptions.PasswordMismatchException;
import com.swiftmart.usermgmtservice.models.Token;
import com.swiftmart.usermgmtservice.models.User;
import com.swiftmart.usermgmtservice.repositories.TokenRepository;
import com.swiftmart.usermgmtservice.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private  TokenRepository tokenRepository;

    public UserServiceImpl(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder,
                           TokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenRepository = tokenRepository;
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
        if (optionalUser.isEmpty()) {
            //redirect to signup
            return null;
        }
        User user = optionalUser.get();
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            //password mismtach
            //we should throw an exception here.ie.PasswordMismatchException.
            throw new PasswordMismatchException("Invalid Password");
        }

        //SUCCESSFUL of login--FLOW:
        //if control reaches here, means login is successful.
        Token token = new Token();
        token.setUser(user);
        //generate a random token value and set it to token object.
        //token.setTokenValue(java.util.UUID.randomUUID().toString());
        token.setTokenValue(RandomStringUtils.randomAlphanumeric(128));//pnp:128 alphanumeric chars, very difficult to guess.
        //set the expiry time of token to 1 hour from now.

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, 30);
        Date expiryDate = calendar.getTime();

        //token.setExpiryTime(System.currentTimeMillis() + 3600 * 1000);//
        //Note:3600*1000 means 1 hour in milliseconds.

        token.setExpiryDate(expiryDate);//This sets expiry of token.

        //Now we need to save this token to DB.But we have not created TokenRepository yet.
        //return token;
        token = tokenRepository.save(token);
        //return null;
        return token;
    }

    @Override
    public User validateToken(String tokenValue) {
        return null;
    }
}
