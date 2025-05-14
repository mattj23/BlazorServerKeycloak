using System.Collections.ObjectModel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BlazorServerKeycloak;

/// <summary>
/// A simple, built in IApiKeySource that checks keys against a static dictionary of hash/entity pairs.
/// </summary>
public class StaticApiKeySource(Dictionary<string, string> keys) : IApiKeySource
{
    private readonly IReadOnlyDictionary<string, string> _keys = keys;

    public Task<IReadOnlyDictionary<string, string>> GetApiKeys()
    {
        return Task.FromResult(_keys);
    }

    public Task<string?> VerifyKey(string b64Hash)
    {
        if (_keys.ContainsKey(b64Hash)) return Task.FromResult<string?>(_keys[b64Hash]);
        return Task.FromResult<string?>(null);
    }
}

public static class StaticApiKeySourceExtensions
{
    /// <summary>
    /// Adds a simple, built in IApiKeySource built from a configuration section of string-string pairs where the
    /// key is the entity name and the value is a base-64 encoded string of the SHA256 hash of the password to be sent
    /// in the X-API-KEY header. Be aware that multiple entities with the same password cannot be distinguished between,
    /// these should be uuid-style generated keys.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="config">A configuration section consisting of string/string pairs</param>
    public static void AddStaticApiKeys(this IServiceCollection services, IConfigurationSection config)
    {
        var keys = config.Get<Dictionary<string, string>>();
        services.AddSingleton<IApiKeySource>(new StaticApiKeySource(keys!.ToDictionary(p => p.Value, p => p.Key)));
    }
}