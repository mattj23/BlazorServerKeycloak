using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace BlazorServerKeycloak;
#pragma warning restore IDE0130 // Namespace does not match folder structure

public static class ClaimExtensions
{
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
