# SMAC Platform Agent Authentication Server
This sample project uses [`OpenIddict`](https://documentation.openiddict.com) to implement `OpenID Connect` server and token validation support in ASP.NET Core 7.0 application. It can be used as a project reference to add `OpenID Connect`/`OAuth 2.0` support.

## Getting started
The following are the steps to successfully integrate OpenIddict. To make the guide backward compatible to pre ASP.NET Core 6.0, it is using the `traditional hosting model` instead of the new `minimal hosting model`.
- Install the [.NET Core 3.1 (or later) tooling](https://www.microsoft.com/net/download).
- Have an existing project or create a new one: when creating a new project using Visual Studio's default ASP.NET Core template, using individual user accounts authentication is strongly recommended as it automatically includes the default ASP.NET Core Identity UI, based on Razor Pages.
- Update your `.csproj` file to reference the latest `OpenIddict` packages.
    ```
    <PackageReference Include="OpenIddict.AspNetCore" Version="4.1.0" />
    <PackageReference Include="OpenIddict.EntityFrameworkCore" Version="4.1.0" />
    ```
- Configure the OpenIddict core, server and validation services in `Startup.ConfigureServices`.
    ```
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure Entity Framework Core to use Microsoft SQL Server.
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddOpenIddict()

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
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserinfoEndpointUris("connect/userinfo");

                // Mark the "email" and "profile" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile);

                // Enable the authorization code flow.
                options.AllowAuthorizationCodeFlow();

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
        services.AddHostedService<Worker>();
    }
    ```
- Make sure the ASP.NET Core authentication middleware is correctly registered at the right place.
    ```
    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(options =>
        {
            options.MapControllers();
            options.MapDefaultControllerRoute();
        });
    }
    ```
- Update your Entity Framework Core context registration to register the OpenIddict entities.
    ```
    services.AddDbContext<ApplicationDbContext>(options =>
    {
        // Configure Entity Framework Core to use Microsoft SQL Server.
        options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

        // Register the entity sets needed by OpenIddict.
        // Note: use the generic overload if you need to replace the default OpenIddict entities.
        options.UseOpenIddict();
    });
    ```
    > By default, the OpenIddict Entity Framework Core integration uses string as the default type for primary keys. To use a different type, read [Entity Framework Core integration : Use a custom primary key type](https://documentation.openiddict.com/integrations/entity-framework-core.html#use-a-custom-primary-key-type).
- Create your own authorization controller. Implementing a custom authorization controller is required to allow OpenIddict to create tokens based on the identities and claims you provide.
    ```
    public class AuthorizationController : Controller
    {
        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            // Perform user authentication and client validation. Please refer to sample for example.
            // ...
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Token()
        {
            // Perform user validation and prepare claims for token generation. Please refer to sample for example.
            // ...
        }
    }
    ```
- Register your client application (e.g from an IHostedService implementation).
    ```
    public class Worker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public Worker(IServiceProvider serviceProvider)
            => _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("smac_platform") is null)
            {
                var client = new OpenIddictApplicationDescriptor
                {
                    ClientId = "smac_platform",
                    ClientSecret = "CF9CA533-0D51-445B-8B52-08B97C389A73",
                    DisplayName = "My client application",
                    Permissions =
                    {
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Authorization,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.ResponseTypes.Code
                    }
                };
                client.RedirectUris.Add(new Uri("https://smac-poc.mcs-group.com.my/signin-smacauth"));
                await manager.CreateAsync(client);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
    ```
- Before running the application, make sure the database is updated with OpenIddict tables by running `Add-Migration` and `Update-Database`.