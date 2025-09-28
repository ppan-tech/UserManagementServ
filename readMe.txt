Create DB, create DB user and assign all privileges to the DB user:
$mysql -u root -p
pass:admin12kafour-42kaone
create database userMgmtService;
use userMgmtService;
create user userMgmtServiceuser;
grant all privileges on userMgmtService.* to userMgmtServiceuser;
------
Spring security is not aloowing any api without security.Security-filter-chain is there.So every API  request has to passed through that filter.We should permit at least permit signup & login Request.So we will use SecurityFilterChain(given by spring Security).By default
every API request has to be authorized.But we should bypass Security for these tow flows:signup & login, then only someone can work with this API.
Note that by default when you make request from one machine to other, as per these properties(cors & csrf) brower blocks them,so we need to disable them.
cors
csrf
@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable();
        httpSecurity.cors().disable();
        httpSecurity.authorizeHttpRequests(
                authorize -> authorize.anyRequest().permitAll()
        );

        return httpSecurity.build();
    }
    --
    Hence, although APP is working fine, but it is not secure.So if i send this req.
    curl --location --request GET 'http://localhost:8080/users/signup' \
    --header 'Content-Type: application/json' \
    --header 'Cookie: JSESSIONID=72B0FEF24377721A9135729895A70CE5' \
    --data-raw '{
        "name":"Punepant",
        "email":"PunePant@gmail.com",
        "password":"pw123456"
    }'

    then i am getting response as
    HTTP 401 (unauthorized)
    i.e.
    {
        "timestamp": "2024-06-26T09:55:21.841+00:00",
        "status": 401,
        "error": "Unauthorized",
        "path": "/users/signup"
    }
   --------
   Now after adding this filter chain and allowing all calls, the user is created in DB and signup is successful.
    But this is not secure, as anyone can call any API without authentication.
    The insert stmt executed is:
        Hibernate: select u1_0.id,u1_0.created_at,u1_0.email,u1_0.last_updated_at,u1_0.name,u1_0.password from users u1_0 where u1_0.email=?
        Hibernate: insert into users (created_at,email,last_updated_at,name,password) values (?,?,?,?,?)
  ---------
  Now both of these API calls works:
 ==singup API call:
  curl --location 'http://localhost:8080/users/signup' \
  --header 'Content-Type: application/json' \
  --header 'Cookie: JSESSIONID=72B0FEF24377721A9135729895A70CE5' \
  --data-raw '{
      "name":"PPant2",
      "email":"punepant2@gmail.com",
      "password":"pw123456"
  }'
==login API call:
curl --location 'http://localhost:8080/users/login' \
--header 'Content-Type: application/json' \
--header 'Cookie: JSESSIONID=72B0FEF24377721A9135729895A70CE5' \
--data-raw '{
    "name":"PPant2",
    "email":"punepant2@gmail.com",
    "password":"pw123456"
}'
\\=========
Also check the DB, user is created successfully.
=======output from login API call:
{
    "tokenValue": "O3UnmHBVTcJFSVHkF38mcspKsJKAkSKWEojMb1gW5cbfPAihdyy3vNcEEHHIPQ0yrDO12QypIFkde3ivdqTyW8jyccJ7q6EF94RBtBoJ3Qo85j0HJ9ARUWys2iSrfYvF"
}
========
now we will check whether this token value is valid or not
------
we are asking JPA to listen to the entity changes and update the created_at and last_updated_at fields automatically.
So we need to enable JPA auditing in the main class of the project as:
@EnableJpaAuditing
@SpringBootApplication
public class UserMgmtServiceApplication {
}
---Also go to the BaseModel class and add these two annotations:(also @EnntityListeners at class level)
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "last_updated_at")
    private Instant lastUpdatedAt;
------------
The flow will be like this:
    we signup and created a token and store it in DB.
    when we call any API, we will send this token in header as:
    Authorization
    Bearer <tokenValue>
    then we will intercept this request using a filter and extract this token from header and validate it
    if valid, we will allow the request to go to the controller
    if not valid, we will return 401 unauthorized
    for this we will create a filter class and implement the logic.
    we will also need to create a service class to validate the token.
    we will also need to update the security filter chain to use this filter.
    we will also need to create a custom exception class for unauthorized access.
    we will also need to create a response class for the token.
    we will also need to update the user entity to have a one to many relationship with the token entity.
    we will also need to create a token entity to store the token in DB.
    we will also need to create a token repository to interact with the token entity.
    we will also need to create a token service to handle the token logic.
    we will also need to create a token controller to handle the token API.

    Also on login-API-call, we will return TokenDto, which will have just the token Value.
    Now we will call validateToken-API to get the this token validated and that Validate API will return the UserDto object now.

    DTO-some details:
        DTOs are used to hide details from client.And client will never interact with service directly.So service need
        not to retunr DTO to controller, whereas it can return the model class object to controller.
        But controller should return DTO to client.
        So controller will convert model class object to DTO and return it to client.

Details of encode() method of BCryptPasswordEncoder class:
    public String encode(CharSequence rawPassword) {
        String salt;
        if (this.strength > 0) {
            if (this.random != null) {
                salt = BCrypt.gensalt(this.strength, this.random);
            } else {
                salt = BCrypt.gensalt(this.strength);
            }
        } else {
            salt = BCrypt.gensalt();
        }
        return BCrypt.hashpw(rawPassword.toString(), salt);
    }
    ----------
Details of matches() method of BCryptPasswordEncoder class:
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            this.logger.warn("Empty encoded password");
            return false;
        } else if (!encodedPassword.startsWith("$2")) {
            this.logger.warn("Encoded password does not look like BCrypt");
            return false;
        } else {
            return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
        }
    }
    ----------
Details of gensalt() method of BCrypt class:
    public static String gensalt(int log_rounds, SecureRandom random) {
        StringBuilder rs = new StringBuilder();
        byte[] rnd = new byte[16];
        random.nextBytes(rnd); //generates random bytes and places them in rnd byte array


The encode method of BCryptPasswordEncoder automatically generates a random salt for each password. It combines
the salt with the password and hashes them using the BCrypt algorithm. This ensures that even identical passwords
will have different hashes, improving security. The salt is stored as part of the resulting hash string.
----------encode method details--till here--

----Before JWT--implementation----till now our flow---
Till now., our flow was : user calls setup-API, with email and password.We will then convert the password into Hash using BcryptPasswordEncoder.encode()
method, which internally uses salt, which it generates itself and then we store this email and hashed password into DB in users table, where
we store userid,hashed password etc.
We returned the user-object to the caller, with userId init.

Now in login-API call, user will send email and password.
We will fetch the user details(userid, hashed_password) from DB-table 'users' using email_Id and then we will use
    BcryptPasswordEncoder.matches(hashedPasswd-from-DB, user-sent-password-to-login) method
to match the password sent by user with the hashed password stored in DB.
This method internally extracts the salt from the hashed password and uses it to hash the password sent by user for login.
If both hashes match, then password is correct.
If password is correct, we will generate a new token using Apache commons and store it in DB(tokens table) and return this token to user.
If password is incorrect, we will return 401 unauthorized.

Note:Tokens table store all the tokens, their expiry time and the userId with which they are associated.For eveyr login we genberate a token so we will
store in this Table-token.

Also we have created an authCommon Bean class, in ProductServicem which calls this user-Service, by calling its valdiateToken-API, to validate the token.
If success then Product-Svc retunrs the product; but if user-service returns un-Authorized, then throws exception that unauthorized.
This is how we are using user-service in product-service.
------
Now we will implement JWT token based authentication.

JWT token has three parts:
Header
Payload
Signature
The header contains the type of token (JWT) and the signing algorithm (e.g., HMAC SHA256 or RSA).
The payload contains the claims. Claims are statements about an entity (typically, the user) and
additional data. There are three types of claims: registered, public, and private claims.
The signature is used to verify that the sender of the JWT is who it says it is and
to ensure that the message wasn't changed along the way.

To create the signature part you have to take the encoded header, the encoded payload,
a secret, the algorithm specified in the header, and sign that.

The signature is used to verify that the sender of the JWT is who it says it is and
to ensure that the message wasn't changed along the way.

To create the signature part you have to take the encoded header, the encoded payload,
a secret, the algorithm specified in the header, and sign that.

For example if you want to use the HMAC SHA256 algorithm, the signature will be created
in the following way:
HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    secret)
The output will be three Base64-URL strings separated by dots that can be easily passed in
HTML and HTTP environments, while being more compact than other token formats such as XML-based tokens.
This compactness makes JWTs a good choice to be passed in HTML and HTTP environments.

The JWT can also be encrypted to provide secrecy between parties. However, since most use cases
do not require encryption, this specification does not cover encrypted JWTs.
If you want to encrypt the JWT, you can use JWE (JSON Web Encryption).
------
We will use jjwt library to create and validate JWT tokens.
We will create a JwtService class to handle JWT token creation and validation.
We will update the UserService class to use JwtService to create JWT token on login.
We will update the JwtAuthFilter class to validate JWT token instead of the token stored in DB.
We will update the SecurityFilterChain to use JwtAuthFilter.
We will update the UserController to return JWT token on login.
We will update the TokenDto class to TokenResponseDto class to return JWT token.
We will update the User entity to remove the relationship with Token entity.
We will remove the Token entity and Token repository.
We will remove the TokenService class.
We will update the UserRepository to remove the Token entity.
We will update the UserServiceImpl class to remove the Token entity.
We will update the UserController class to remove the Token entity.
We will update the AuthCommon class in ProductService to validate JWT token.
We will update the application.properties file to add JWT secret and expiration time.
We will test the application to ensure everything is working fine.
------
We will add the following properties in application.properties file:
jwt.secret=your_jwt_secret_key
jwt.expiration=3600000
------
We will create a JwtService class to handle JWT token creation and validation.
package com.example.usermgmtservice.service;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.Date;
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private long jwtExpirationMs;
    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            // Log the exception
        }
        return false;
    }
}
------
We will update the UserServiceImpl class to use JwtService to create JWT token on login.
package com.example.usermgmtservice.service.impl;
import com.example.usermgmtservice.dto.TokenResponseDto;
import com.example.usermgmtservice.model.User;
import com.example.usermgmtservice.repository.UserRepository;
import com.example.usermgmtservice.service.JwtService;
import com.example.usermgmtservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Override
    @Transactional
    public User signup(User user) {
        Optional<User> existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser.isPresent()) {
            throw new RuntimeException("User with email " + user.getEmail() + " already exists");
        }
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        return userRepository.save(user);
    }
    @Override
    public TokenResponseDto login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }
        String token = jwtService.generateToken(user.getEmail());
        return new TokenResponseDto(token);
    }
    @Override
    public User validateToken(String token) {
        if (!jwtService.validateToken(token)) {
            throw new RuntimeException("Invalid token");
        }
        String email = jwtService.getEmailFromToken(token);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found for the provided token"));

}



}
------
We will update the JwtAuthFilter class to validate JWT token instead of the token stored in DB.
package com.example.usermgmtservice.filter;
import com.example.usermgmtservice.service.JwtService;
import com.example.usermgmtservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import  javax.servlet.FilterChain;
import  javax.servlet.ServletException;
import  javax.servlet.http.HttpServletRequest;
import  javax.servlet.http.HttpServletResponse;
import  org.springframework.web.filter.OncePerRequestFilter;
import  java.io.IOException;
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserService userService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtService.validateToken(token)) {
                // Token is valid, proceed with the request
                filterChain.doFilter(request, response);
                return;
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }





}
------
We will update the SecurityFilterChain to use JwtAuthFilter.
package com.example.usermgmtservice.config;
import com.example.usermgmtservice.filter.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter jwtAuthFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable();
        httpSecurity.cors().disable();
        httpSecurity.authorizeHttpRequests(
                authorize -> authorize
                        .antMatchers("/users/signup", "/users/login").permitAll()
                        .anyRequest().authenticated()
        );
        httpSecurity.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }


}
------
We will update the UserController to return JWT token on login.
package com.example.usermgmtservice.controller;
import com.example.usermgmtservice.dto.TokenResponseDto;
import com.example.usermgmtservice.dto.UserDto;
import com.example.usermgmtservice.model.User;
import com.example.usermgmtservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;
    @PostMapping("/signup")
    public ResponseEntity<UserDto> signup(@RequestBody User user) {
        User createdUser = userService.signup(user);
        UserDto userDto = new UserDto(createdUser.getId(), createdUser.getName(), createdUser.getEmail());
        return new ResponseEntity<>(userDto, HttpStatus.CREATED);
    }
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(@RequestBody User user) {
        TokenResponseDto tokenResponse = userService.login(user.getEmail(), user.getPassword());
        return new ResponseEntity<>(tokenResponse, HttpStatus.OK);
    }
    @GetMapping("/validateToken")
    public ResponseEntity<UserDto> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            User user = userService.validateToken(token);
            UserDto userDto = new UserDto(user.getId(), user.getName(), user.getEmail());
            return new ResponseEntity<>(userDto, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }




}
------
We will update the TokenDto class to TokenResponseDto class to return JWT token.
package com.example.usermgmtservice.dto;
public class TokenResponseDto {

    private String tokenValue;
    public TokenResponseDto(String tokenValue) {
        this.tokenValue = tokenValue;
    }
    public String getTokenValue() {
        return tokenValue;
    }
    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }




}
------
We will update the User entity to remove the relationship with Token entity.
package com.example.usermgmtservice.model;
import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import java.time.Instant;
@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener.class)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false)
    private String name;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = false)
    private String password;
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @LastModifiedDate
    @Column(name = "last_updated_at")
    private Instant lastUpdatedAt;
    public Long getId() {
        return id;

    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public Instant getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    public Instant getLastUpdatedAt() {
        return lastUpdatedAt;
    }

    }
    public void setLastUpdatedAt(Instant lastUpdatedAt) {
        this.lastUpdatedAt = lastUpdatedAt;
    }
}
------
We will remove the Token entity and Token repository.
package com.example.usermgmtservice.model;
import jakarta.persistence.*;
@Entity
@Table(name = "tokens")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String tokenValue;
    @Column(nullable = false)
    private           Long userId;

    @Column(nullable  = false)
    private Long expiryTime;
    public Long getId() {
        return id;


    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getTokenValue() {
        return tokenValue;
    }
    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }
    public Long getUserId() {
        return userId;
    }
    public void setUserId(Long userId) {
        this.userId = userId;
    }
    public Long getExpiryTime() {
        return expiryTime;
    }
    public void setExpiryTime(Long expiryTime) {
        this.expiryTime = expiryTime;
    }
}
------
package com.example.usermgmtservice.repository;
import com.example.usermgmtservice.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    Token findByTokenValue(String tokenValue);



}
------
We will remove the TokenService class.
package com.example.usermgmtservice.service;
import com.example.usermgmtservice.model.Token;
public interface TokenService {
    Token createToken(Long userId);
    Token validateToken(String tokenValue);
    void deleteToken(String tokenValue);


}
------
We will update the UserRepository to remove the Token entity.
package com.example.usermgmtservice.repository;
import com.example.usermgmtservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    // Removed Token related methods

}
------
We will update the UserServiceImpl class to remove the Token entity.
package com.example.usermgmtservice.service.impl;
import com.example.usermgmtservice.dto.TokenResponseDto;
import com.example.usermgmtservice.model.User;
import com.example.usermgmtservice.repository.UserRepository;
import com.example.usermgmtservice.service.JwtService;
import com.example.usermgmtservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;
@Service


---------------------------public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Override
    @Transactional
    public User signup(User user) {
        Optional<User> existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser.isPresent()) {
            throw new RuntimeException("User with email " + user.getEmail() + " already exists");
        }
        String hashedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(hashedPassword);
        return userRepository.save(user);
    }
    @Override
    public TokenResponseDto login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid email or password");
        }
        String token = jwtService.generateToken(user.getEmail());
        return new TokenResponseDto(token);
    }

    @Override
    public User validateToken(String token) {








---
As i have implmented JWT, for pyaload part.SO i hardcoded payload part for Deepak's details. and this is the token i get:
eyJhbGciOiJub25lIn0.ewogICAiZW1haWwiOiAiZGVlcGFrQGdtYWlsLmNvbSIsCiAgICJyb2xlcyI6IFsKICAgICAgImluc3RydWN0b3IiLAogICAgICAidGEiCiAgIF0sCiAgICJleHBpcnlEYXRlIjogIjIybmRTZXB0MjAyNiIKfQ.

now putting this token in http://jwt.io for decoding, i got the same details as the hard coded payload i put inside it.
So this confirms that JWT is working fine.
------







