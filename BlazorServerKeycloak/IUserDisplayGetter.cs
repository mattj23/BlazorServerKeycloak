using System.Security.Claims;

namespace BlazorServerKeycloak;

public interface IUserDisplayGetter
{
    Task<string?> Get(ClaimsPrincipal user);
}