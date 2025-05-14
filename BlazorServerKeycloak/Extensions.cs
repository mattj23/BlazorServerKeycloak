using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorServerKeycloak;

public static class Extensions
{
    public static AuthenticationBuilder AddKeycloak(this IServiceCollection services, IConfigurationSection config)
    {
        var oidcOptions = new OpenIdConnectOptions();
        config.Bind(oidcOptions);
        services.AddSingleton(oidcOptions);

        var builder = services.AddAuthentication(options =>
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

        return builder;
    }

    /// <summary>
    /// Gets an identity claim by the supplied <paramref name="type"/>
    /// </summary>
    /// <param name="source">Claim to search</param>
    /// <param name="type">Claim type</param>
    /// <returns></returns>
    public static Claim GetClaim(this ClaimsIdentity source, string type)
    {
        if (source is null || string.IsNullOrEmpty(type))
        {
            return default!;
        }

        return source.FindFirst(type) ?? default!;
    }

    /// <summary>
    /// Gets the value from <paramref name="source"/> by <paramref name="type"/>
    /// </summary>
    /// <param name="source">Claim to search</param>
    /// <param name="type">Claim type</param>
    /// <returns>string containing value of claim or an empty string</returns>
    public static string GetClaimValue(this ClaimsIdentity source, string type)
    {
        if (source == null || string.IsNullOrEmpty(type))
        {
            return string.Empty;
        }

        return source.FindFirst(type)?.Value ?? string.Empty;
    }

    /// <summary>
    /// Adds or updates a identity claim
    /// </summary>
    /// <returns></returns>
    public static ClaimsIdentity SetClaim(this ClaimsIdentity source, Claim claim)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        ArgumentNullException.ThrowIfNull(claim, nameof(claim));

        if (source.FindFirst(claim.Type) != null)
        {
            source.RemoveClaim(claim);
        }

        source.AddClaim(claim);
        return source;
    }

    /// <summary>
    /// Adds or updates a identity claim
    /// </summary>
    /// <returns></returns>
    public static ClaimsIdentity SetClaimValue(this ClaimsIdentity source, string type, string value)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));

        Claim claim = new(type, value);

        return source.SetClaim(claim);
    }

    /// <summary>
    /// Adds or updates a identity claim
    /// </summary>
    /// <returns></returns>
    public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long value)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));

        Claim claim = new(type, value.ToString());

        return source.SetClaim(claim);
    }

    /// <summary>
    /// Adds or updates a identity claim
    /// </summary>
    /// <returns></returns>
    public static ClaimsIdentity AddOrUpdateClaim(this ClaimsIdentity source, string type, long? value)
    {
        ArgumentNullException.ThrowIfNull(source, nameof(source));
        
        Claim claim = new(type, value.ToString()!);

        return source.SetClaim(claim);
    }

    public static ClaimsIdentity SetIdentityClaims(this ClaimsIdentity source, string accessToken, string refreshToken)
    {
        return source
            .SetClaimValue(ClaimType.AccessToken, accessToken)
            .SetClaimValue(ClaimType.RefreshToken, refreshToken)
            .SetClaimValue(ClaimType.AccessTokenExpires, ((DateTimeOffset)new JwtSecurityToken(accessToken).ValidTo).ToUnixTimeSeconds().ToString())
            .SetClaimValue(ClaimType.RefreshTokenExpires, ((DateTimeOffset)new JwtSecurityToken(refreshToken).ValidTo).ToUnixTimeSeconds().ToString());
    }
}