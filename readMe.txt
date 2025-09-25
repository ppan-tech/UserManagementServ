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
