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
