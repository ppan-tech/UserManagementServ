package com.swiftmart.usermgmtservice.repositories;

import com.swiftmart.usermgmtservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import  java.util.Optional; 

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(Long id);

    Optional<User> findByEmail(String email);
}
//Note:every repository should be an interface and should extend JpaRepository or CrudRepository.