package com.swiftmart.usermgmtservice.services;

import com.swiftmart.usermgmtservice.exceptions.InvalidTokenException;
import com.swiftmart.usermgmtservice.exceptions.PasswordMismatchException;
import com.swiftmart.usermgmtservice.models.Token;
import com.swiftmart.usermgmtservice.models.User;

public interface UserService {
    User signup(String name, String email, String password);

    String login(String email, String password) throws PasswordMismatchException;

    User validateToken(String tokenValue) throws InvalidTokenException;
}
