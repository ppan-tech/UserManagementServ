package com.swiftmart.usermgmtservice.repositories;

import com.swiftmart.usermgmtservice.models.Token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    @Override
    Token save(Token token);

    //Declared Queries -> Hibernate
    // select * from tokens where token_value = ? and expiry_at > current_time.
    Optional<Token> findByTokenValueAndExpiryDateAfter(String tokenValue, Date currentDate);

    @Override
    Optional<Token> findById(Long aLong);
}
//sytax is : findByXAnd/OR/YBetween etc.


