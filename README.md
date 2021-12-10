# BlazorServerKeycloak
Razor class library to add OIDC authentication to a Blazor server-side application

## Motivation

Blazor's server-side hosting model is extremely fast and convenient to develop with, and is more than adequate for internal line-of-business type applications which, by nature, have relatively few simultaneous users.  

Keycloak is an OpenIDConnect provider that is especially useful for internal applications because it can federate with LDAP (and Active Directory in particular) and effectively offer authentication against it through OIDC, even going so far as to map AD security groups as realm roles which are available as claims in the client application.

Nominally, the combination of server-side Blazor authenticated against Keycloak would be an ideal platform for rapidly developing and deploying internal business applications while hooking into existing centralized identity and access management tools common in small business infrastructure.  However, with the server-side hosting model the use of the SignalR hub and the lack of an `HttpContext` in established connections means that typical authentication schemes are not straightforward to implement.

This is a Razor class library which borrows heavily from https://github.com/vip32/aspnetcore-keycloak and packages all of the necessary components for authentication against Keycloak using OpenID Connect, including the configuration, the sign-in and sign-out endpoints, and an authorization requirement and handler to map to imported realm roles.

## Preparing Keycloak

These instructions assume you have a Keycloak instance up and running and you have administrator access to it.  Setting up Keycloak and federating it with Active Directory or LDAP is beyond the scope of this guide.

Preparing Keycloak to provide authentication and authorization to your application involves configuring a Keycloak *client*, in which the *client* is your application.

### Creating the client

In the desired Keycloak *realm* under the "Configure" menu, select "Clients".  You will be presented with a table of existing clients for realm.  Select the "Create" option to create a new client.

|Parameter|Value|
|-|-|
|Client ID| A human readable, URI safe text string which identifies the application.  For example, "test-app", or "example-application-name"|
|Client Protocol|Choose "openid-connect"|
|Root URL|You may leave this blank during development, but ultimately should point to the root URL for the application|

After setting the values, select "Save".

### Client configuration

After saving the new client you will be brought to the client editing page.  This can also be accessed by selecting "Edit" for a specific client from the table in the "Clients" page.  There are several tabs across the top, select the "Settings" tab.

Set the following parameters:

|Parameter|Value|
|-|-|
|Name|Typically I make this identical to the client ID, but it can also be a friendlier display name|
|Enabled|Set to "ON"|
|Access Type|Set to "confidential"|
|Standard Flow Enabled|Set to "ON"|
|Implicit FLow Enabled|Set to "ON"|
|Direct Access Grants Enabled|Set to "ON"|
|Valid Redirect URIs|See the detailed section below|
|Web Origins|I typically set this to "+" or "*"|

Be sure to save changes when done.

#### Valid Redirect URIs
These are URIs where Keycloak will allow redirection during the OIDC flow.  See the detailed section below.They must include the application OIDC endpoints or the process will not work.  For local development this will need to point at the localhost/port combination, for deployment it will need to point at the application's URI.  The endpoints `signin-odic` and `signout-oidc` will be required.

### Client Credentials

On the Client edit page, select the "Credentials" tab.  The client secret will be a hexadecimal text token in a grayed out box labeled "Secret".  This is the client secret that will be used in the configuration of the ASP.NET project.  


## Setup

### Installation

#### Nuget Package
Todo: Nuget package

#### Git submodule

```bash
git submodule add git@github.com:mattj23/BlazorServerKeycloak.git
```
In your solution file, add the existing project `BlazorServerKeycloak.csproj`.  Then in your Blazor server-side ASP.NET 6 project's dependencies add a project reference to `BlazorServerKeycloak`.


### Integrate into project

In the new, simplified ASP.NET 6.0 setup's `Program.cs` file:

```csharp

```

