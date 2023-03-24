using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SmacAuthServer;
using SmacAuthServer.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);

    // Register the entity sets needed by OpenIddict.
    // Note: use the generic overload if you need to replace the default OpenIddict entities.
    options.UseOpenIddict();
});
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddRazorPages();

builder.Services.AddOpenIddict()
    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
        // Note: call ReplaceDefaultEntities() to replace the default entities.
        options.UseEntityFrameworkCore()
                .UseDbContext<ApplicationDbContext>();
    })

    // Register the OpenIddict server components.
    .AddServer(options =>
    {
        // Enable the authorization, token and userinfo endpoints.
        options.SetAuthorizationEndpointUris(builder.Configuration["OpenIddict:Endpoints:Authorization"]!)
               .SetTokenEndpointUris(builder.Configuration["OpenIddict:Endpoints:Token"]!)
               .SetUserinfoEndpointUris(builder.Configuration["OpenIddict:Endpoints:Userinfo"]!);

        options.AllowAuthorizationCodeFlow();

        // Expose all the supported claims in the discovery document.
        options.RegisterClaims(builder.Configuration.GetSection("OpenIddict:Claims").Get<string[]>()!);

        // Expose all the supported scopes in the discovery document.
        options.RegisterScopes(builder.Configuration.GetSection("OpenIddict:Scopes").Get<string[]>()!);

        // Register the signing and encryption credentials.
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Register the ASP.NET Core host and configure the ASP.NET Core options.
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableAuthorizationRequestCaching();
    })

    // Register the OpenIddict validation components.
    .AddValidation(options =>
    {
        // Import the configuration from the local OpenIddict server instance.
        options.UseLocalServer();

        // Register the ASP.NET Core host.
        options.UseAspNetCore();

        // Enable authorization entry validation, which is required to be able
        // to reject access tokens retrieved from a revoked authorization code.
        options.EnableAuthorizationEntryValidation();
    });

// Register the worker responsible of seeding the database with the sample clients.
// Note: in a real world application, this step should be part of a setup script.
builder.Services.AddHostedService<Worker>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

app.Run();