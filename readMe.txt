Create DB, create DB user and assign all privileges to the DB user:
$mysql -u root -p
pass:admin12kafour-42kaone
create database userMgmtService;
use userMgmtService;
create user userMgmtServiceuser;
grant all privileges on userMgmtService.* to userMgmtServiceuser;
