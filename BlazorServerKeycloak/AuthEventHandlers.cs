using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorServerKeycloak;
public static class AuthEventHandlers
{
    public static async Task OnValidatePrincipalAsync(CookieValidatePrincipalContext context, OpenIdConnectOptions oidcOptions)
    {
        // this event is fired everytime the cookie has been validated by the cookie middleware, so basically during every authenticated request.
        // the decryption of the cookie has already happened so we have access to the identity + user claims
        // and cookie properties - expiration, etc..
        // source: https://github.com/mderriey/aspnet-core-token-renewal/blob/2fd9abcc2abe92df2b6c4374ad3f2ce585b6f953/src/MvcClient/Startup.cs#L57
        if (context.Principal is null || context.Principal!.Identity is null)
        {
            return;
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long expires = context.Properties.ExpiresUtc.GetValueOrDefault().ToUnixTimeSeconds();

        if (now >= expires)
        {
            TokenResponse response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = oidcOptions.Authority +
                          "/protocol/openid-connect/token",
                ClientId = oidcOptions.ClientId,
                ClientSecret = oidcOptions.ClientSecret,
                RefreshToken =
                    ((ClaimsIdentity)context.Principal.Identity)
                    .GetClaimValue(ClaimType
                        .RefreshToken)
            }).ConfigureAwait(false);

            if (!response.IsError)
            {
                ((ClaimsIdentity)context.Principal.Identity)
                    .SetIdentityClaims(response.AccessToken, response.RefreshToken);

                context.ShouldRenew = true;
            }
        }
    }

    public static Task OnTokenValidated(TokenValidatedContext context)
    {
        // this event is called after the OIDC middleware received the authorization code,
        // redeemed it for an access token + a refresh token and validated the identity token
        ((ClaimsIdentity)context.Principal!.Identity!)
            .SetIdentityClaims(context.TokenEndpointResponse!.AccessToken!,
                context.TokenEndpointResponse.RefreshToken);

        context.Properties!.ExpiresUtc =
            new JwtSecurityToken(context.TokenEndpointResponse.AccessToken)
                .ValidTo; // align expiration of the cookie with expiration of the access token
        context.Properties.IsPersistent =
            true; // so that we don't issue a session cookie but one with a fixed expiration

        return Task.CompletedTask;
    }
}
