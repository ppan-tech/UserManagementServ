package com.swiftmart.usermgmtservice.repositories;

import com.swiftmart.usermgmtservice.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

}
