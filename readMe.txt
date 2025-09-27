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
