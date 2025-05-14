using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BlazorServerKeycloak.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace BlazorServerKeycloak.Authorization;

public class ApiKeyRequirementHandler(IApiKeySource apiKeySource) : AuthorizationHandler<ApiKeyRequirement>
{
    private readonly IApiKeySource _apiKeys = apiKeySource;
    private const string ApiKeyHeaderName = "X-API-KEY";

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyRequirement requirement)
    {
        if (requirement.RealmReq is null && context.User.Identity?.IsAuthenticated == true)
        {
            context.Succeed(requirement);
        }
        else if (context.User.HasClaim(c => c.Type == "user_realm_roles" && 
                                            requirement.RealmReq?.HasRole(c.Value) == true))
        {
            context.Succeed(requirement);
        }
        else if (context.Resource is HttpContext http)
        {
            string? submitted = http.Request.Headers[ApiKeyHeaderName].FirstOrDefault();
            byte[] bytes = Encoding.UTF8.GetBytes(submitted ?? string.Empty);
            string? hashed = Convert.ToBase64String(SHA256.HashData(bytes));

            string? entity = await _apiKeys.VerifyKey(hashed);
            if (entity is null) return;

            http.User.AddIdentity(new ClaimsIdentity([new Claim("ApiEntity", entity)]));
            context.Succeed(requirement);
        }
    }
}

public static class ApiKeyExtensions
{
    public static string IdentityName(this HttpContext context)
    {
        return context?.User.Identity?.Name
            ?? context?.User?.Claims?.FirstOrDefault(c => c.Type == "ApiEntity")?.Value
            ?? string.Empty;
        //string? name = context?.User.Identity?.Name;

        //if (name is null)
        //{
        //    var apiClaim = context?.User?.Claims.FirstOrDefault(c => c.Type == "ApiEntity");
        //    name = apiClaim?.Value;
        //}

        //return name;
    }
}