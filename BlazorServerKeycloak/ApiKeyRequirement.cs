using Microsoft.AspNetCore.Authorization;

namespace BlazorServerKeycloak
{
    public class ApiKeyRequirement : IAuthorizationRequirement
    {
        public UserRealmRoleRequirement RealmReq { get; }

        public ApiKeyRequirement(UserRealmRoleRequirement realmReq)
        {
            RealmReq = realmReq;
        }
    }
}