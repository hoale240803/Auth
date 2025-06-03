

using IdentityRolesAndClaims.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Configure SQLite database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity with roles
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Define authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanCreateAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Create"));
    options.AddPolicy("CanEditAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Edit"));
    options.AddPolicy("CanDeleteAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Delete"));
    options.AddPolicy("CanViewAsset", policy =>
        policy.RequireClaim("Permission", "Asset.View"));
    options.AddPolicy("CanCommentAsset", policy =>
        policy.RequireClaim("Permission", "Asset.Comment"));
    options.AddPolicy("CanManageUsers", policy =>
        policy.RequireClaim("Permission", "User.Manage"));
});

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication().AddCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();
// Seed roles and users (for demo purposes)
using (var scope = app.Services.CreateScope())
{
    await SeedData.Initialize(scope.ServiceProvider);
}

app.Run();
