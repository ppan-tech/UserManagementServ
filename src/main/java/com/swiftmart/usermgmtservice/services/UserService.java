package com.swiftmart.usermgmtservice.services;

import com.swiftmart.usermgmtservice.models.Token;
import com.swiftmart.usermgmtservice.models.User;

public interface UserService {
    User signup(String name, String email, String password);

    Token login(String email, String password) ;

    User validateToken(String tokenValue);
}
