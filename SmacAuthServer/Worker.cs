using OpenIddict.Abstractions;
using SmacAuthServer.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SmacAuthServer
{
    public class Worker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public Worker(IServiceProvider serviceProvider)
            => _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

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
                client.RedirectUris.Add(new Uri("https://localhost:44329/signin-smacauth"));
                await manager.CreateAsync(client, cancellationToken);
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}