﻿using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace BlazorServerKeycloak.Shared
{
    public class RedirectToSignin : ComponentBase
    {
        [Inject]
        protected NavigationManager? NavigationManager { get; set; }

        [Inject]
        protected IHttpContextAccessor? Context { get; set; }

        protected override void OnInitialized()
        {
            if (this.Context?.HttpContext?.User.Identity?.IsAuthenticated != true)
            {
                var challengeUri = "/signin?redirectUri=" + System.Net.WebUtility.UrlEncode(this.NavigationManager?.Uri);
                this.NavigationManager?.NavigateTo(challengeUri, true);
            }
        }
    }
}
