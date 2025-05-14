using System.Security.Claims;

namespace BlazorServerKeycloak.Interfaces;

public interface IUserDisplayGetter
{
    Task<string?> Get(ClaimsPrincipal user);
}