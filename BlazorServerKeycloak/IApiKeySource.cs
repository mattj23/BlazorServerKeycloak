using System.Collections.Generic;
using System.Threading.Tasks;

namespace BlazorServerKeycloak
{
    public interface IApiKeySource
    {
        Task<IReadOnlyDictionary<string, string>> GetApiKeys();
    }
}