-- SQLite
select u.Email, uc.ClaimValue
from AspNetUsers as u
inner join AspNetUserRoles on u.Id = AspNetUserRoles.UserId
inner join AspNetRoles on AspNetUserRoles.RoleId = AspNetRoles.Id
inner join AspNetUserClaims  as uc on u.Id = uc.UserId
where u.Email = 'itmanager@example.com'
