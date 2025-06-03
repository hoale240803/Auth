# Init project by cmd

Create a **Auth** solution

```
dotnet new sln --name <name_solution>

dotnet new sln --name AuthLab
```

Create a web api project

```
dotnet add new webapi --Auth
```

Associate a project into solution

```
dotnet sln add <project>

dotnet sln add 01-LoginBasic/BasicAuthApp/BasicAuthApp.csproj
dotnet sln add 03-IdentityRolesAndClaimPolicies\IdentityRolesAndClaims\IdentityRolesAndClaims.csproj
dotnet sln add 04-CustomJWT\CustomJWT\CustomJWT.csproj
dotnet sln add 05-CustomJWTWithRefresh\CustomJWTWithRefresh\CustomJWTWithRefresh.csproj
```

# Structure project

```
AuthLab.sln
│
├── 01-LoginBasic/
├── 02-IdentityIntro/
├── 03-IdentityRoles/
├── 04-ClaimsPolicy/
├── 05-CustomJWT/
├── 06-RefreshToken/
├── 07-2FA-TOTP/
├── 08-SessionManagement/
├── 09-Lockout-Captcha/
└── 10-MultiTenantAuth/

```

Authentication Learning
| Order | Project Folder | Feature Set | Description | Est. Time |
| ----- | ---------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ----------- |
| 1️⃣ | `01-LoginBasic` | ✅ Basic Login/Logout <br> ✅ Register <br> ✅ Password Hash | Use a hardcoded user list or local JSON/EF DB. | **2–3 hrs** |
| 2️⃣ | `02-IdentityIntro` | ✅ ASP.NET Core Identity <br> ✅ EF Core local DB (SQLite) <br> ✅ Register/Login/Logout <br> ✅ Password validation | Leverage full Identity system with SQLite. | **3–5 hrs** |
| 3️⃣ | `03-IdentityRoles` | ✅ Role-based Auth (Admin/User) <br> ✅ Page Restriction | Role-protected Razor or MVC pages. | **2–3 hrs** |
| 4️⃣ | `04-ClaimsPolicy` | ✅ Claims-based Auth <br> ✅ Policy-based Restriction | Add custom claims during login; restrict based on them. | **2–3 hrs** |
| 5️⃣ | `05-CustomJWT` | ✅ JWT Token generation <br> ✅ API authentication <br> ✅ Token validation middleware | Stateless APIs secured by token. | **3–5 hrs** |
| 6️⃣ | `06-RefreshToken` | ✅ JWT + Refresh Tokens <br> ✅ Revoke on logout | Basic token lifecycle with local in-memory/db store. | **3–4 hrs** |
| 7️⃣ | `07-2FA-TOTP` | ✅ Two-Factor via Authenticator App <br> ✅ QR generation | Setup 2FA with `Microsoft.AspNetCore.Identity.UI`. | **3–5 hrs** |
| 8️⃣ | `08-SessionManagement` | ✅ Device/session tracking <br> ✅ Force logout | Track sessions with tokens or Identity sessions. | **4–6 hrs** |
| 9️⃣ | `09-Lockout-Captcha` | ✅ Login attempts throttling <br> ✅ Lockout <br> ✅ Captcha (custom local) | Simulate brute-force protection. | **3–4 hrs** |
| 🔟 | `10-MultiTenantAuth` | ✅ Separate user scopes per tenant <br> ✅ Per-tenant login control | Scoped auth logic per subdomain/org. | **5–7 hrs** |

## Login basic

1. Why it still be used?
   -Internal admin tools
   -Prototypes / PoCs
   -Systems that avoid external dependencies
   -For understanding core auth concepts before Identity

2. What You’ll Build
   A basic ASP.NET Core MVC app with:

   Feature Implementation

   - User Login/Logout Form login, session-based
   - Registration Simple form, save to local file or memory
   - Password Protection Hash with salt using Rfc2898DeriveBytes (PBKDF2)
   - Auth Cookie HttpContext.SignInAsync() with claims
   - Logout HttpContext.SignOutAsync()
   - Middleware [Authorize] to protect pages
