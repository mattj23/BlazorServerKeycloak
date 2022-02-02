using System.Collections.Generic;
using System.Threading.Tasks;

namespace BlazorServerKeycloak
{
    /// <summary>
    /// An interface for an object that will verify API keys against some internal mechanism. One must be accessible
    /// for the ApiKeyRequirementHandler if it is used to enforce api key policies.
    /// </summary>
    public interface IApiKeySource
    {
        /// <summary>
        /// Verify a base-64 string encoding of the hash of an API key. Should return null if no key could be verified,
        /// or the string of the associated identity name if the key is valid and matches an entity.
        /// </summary>
        /// <param name="b64Hash"></param>
        /// <returns></returns>
        Task<string?> VerifyKey(string b64Hash);
    }
}