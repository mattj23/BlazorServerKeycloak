# BlazorServerKeycloak
Razor class library to add OIDC authentication to a Blazor server-side application

## Motivation

Blazor's server-side hosting model is extremely fast and convenient to develop with, and is more than adequate for internal line-of-business type applications which, by nature, have relatively few simultaneous users.  

Keycloak is an OpenIDConnect provider that is especially useful for internal applications because it can federate with LDAP (and Active Directory in particular) and effectively offer authentication against it through OIDC, even going so far as to map AD security groups as realm roles which are available as claims in the client application.

Nominally, the combination of server-side Blazor authenticated against Keycloak would be an ideal platform for rapidly developing and deploying internal business applications while hooking into existing centralized identity and access management tools common in small business infrastructure.  However, with the server-side hosting model the use of the SignalR hub and the lack of an `HttpContext` in established connections means that typical authentication schemes are not straightforward to implement.

This is a Razor class library which borrows heavily from https://github.com/vip32/aspnetcore-keycloak and packages all of the necessary components for authentication against Keycloak using OpenID Connect, including the configuration, the sign-in and sign-out endpoints, and an authorization requirement and handler to map to imported realm roles.

## Setup

### Installation

#### Nuget Package
Todo: Nuget package

#### Git submodule

```bash
git submodule add git@github.com:mattj23/BlazorServerKeycloak.git
```
In your Blazor server-side ASP.NET 6 project, add a project reference to `BlazorServerKeycloak.csproj`.

### Integrate into project

In the new, simplified ASP.NET 6.0 setup's `Program.cs` file:

```csharp

```

