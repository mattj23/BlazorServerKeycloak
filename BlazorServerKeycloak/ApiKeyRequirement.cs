using Microsoft.AspNetCore.Authorization;

namespace BlazorServerKeycloak
{
    /// <summary>
    /// An authorization requirement intended for API endpoints which allows authorization to come either from an
    /// API key passed in the HTTP headers, or via authentication optionally with a user realm role requirement.
    /// </summary>
    public class ApiKeyRequirement : IAuthorizationRequirement
    {
        public UserRealmRoleRequirement? RealmReq { get; }

        /// <summary>
        /// The UserRealmRoleRequirement can be excluded and the authorization handler will authorize if the user
        /// is simply authenticated.  Otherwise the UserRealmRoleRequirement will be used by the authenticator if no
        /// API key header is present.
        /// </summary>
        /// <param name="realmReq"></param>
        public ApiKeyRequirement(UserRealmRoleRequirement? realmReq = null)
        {
            RealmReq = realmReq;
        }
    }
}