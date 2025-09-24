package com.swiftmart.usermgmtservice.repositories;

import com.swiftmart.usermgmtservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import  java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findById(Long id);

    Optional<User> findByEmail(String email);
}
//Note:every repository should be an interface and should extend JpaRepository or CrudRepository.