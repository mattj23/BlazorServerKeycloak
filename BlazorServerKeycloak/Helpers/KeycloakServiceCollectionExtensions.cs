using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Extensions.DependencyInjection;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class KeycloakServiceCollectionExtensions
{
    public static IServiceCollection AddKeycloakAuthentication(this IServiceCollection services, IConfigurationSection config)
    {
        OpenIdConnectOptions oidcOptions = new();
        config.Bind(oidcOptions);
        services.AddSingleton(oidcOptions);

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(options =>
        {
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.Name = "AuthCookie";
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.SlidingExpiration = true;
            options.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = async (context) 
                    => await AuthEventHandlers.OnValidatePrincipalAsync(context, oidcOptions)
            };
        })
        .AddOpenIdConnect(options =>
        {
            options.Authority = oidcOptions.Authority;
            options.ClientId = oidcOptions.ClientId;
            options.ClientSecret = oidcOptions.ClientSecret;
            options.SaveTokens = true;
            options.ResponseType = oidcOptions.ResponseType;
            options.Resource = oidcOptions.Resource; // needed for proper jwt format access_token
            options.RequireHttpsMetadata = oidcOptions.RequireHttpsMetadata; // dev only
            options.GetClaimsFromUserInfoEndpoint =
                oidcOptions.GetClaimsFromUserInfoEndpoint; // does not work together with options.resource

            //options.CallbackPath = oidcOptions.CallbackPath; // "/signin-oidc/"
            //options.SignedOutCallbackPath = oidcOptions.SignedOutCallbackPath; // "/signout-oidc/"
            options.SaveTokens = oidcOptions.SaveTokens;

            options.Scope.Clear();
            foreach (var scope in oidcOptions.Scope) options.Scope.Add(scope);

            options.Events = new()
            {
                OnTokenValidated = (context) 
                    => AuthEventHandlers.OnTokenValidated(context)
            };
            options.TokenValidationParameters = new()
            {
                NameClaimType = "name",
                RoleClaimType = "groups",
                ValidateIssuer = true
            };
        });

        return services;
    }    
}