using System.Collections;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace BlazorServerKeycloak;

public class UserRealmRoleRequirement(params string[] roles) : IAuthorizationRequirement
{
    public bool HasRole(string roleName) => ((IList)roles).Contains(roleName);
}

public class UserRealmRoleRequirementHandler : AuthorizationHandler<UserRealmRoleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, UserRealmRoleRequirement requirement)
    {
        if (context.User.HasClaim(c => c.Type == "user_realm_roles" && requirement.HasRole(c.Value)))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}