using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace BlazorServerKeycloak;

public class ApiKeyRequirementHandler : AuthorizationHandler<ApiKeyRequirement>
{
    private readonly IApiKeySource _apiKeys;

    public ApiKeyRequirementHandler(IApiKeySource k)
    {
        _apiKeys = k;
    }

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
            var submitted = http.Request.Headers[ApiKeyHeaderName].FirstOrDefault();
            var bytes = Encoding.UTF8.GetBytes(submitted ?? string.Empty);
            var hash = SHA256.Create();
            var hashed = Convert.ToBase64String(hash.ComputeHash(bytes));

            var entity = await _apiKeys.VerifyKey(hashed);
            if (entity is null) return;

            http.User.AddIdentity(new ClaimsIdentity(new List<Claim>{ new Claim("ApiEntity", entity)}));
            context.Succeed(requirement);
        }
    }
}

public static class ApiKeyExtensions
{
    public static string IdentityName(this HttpContext context)
    {
        var name = context?.User.Identity?.Name;

        if (name is null)
        {
            var apiClaim = context?.User?.Claims.FirstOrDefault(c => c.Type == "ApiEntity");
            name = apiClaim?.Value;
        }

        return name;
    }
}