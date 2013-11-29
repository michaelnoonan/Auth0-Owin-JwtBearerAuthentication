using System;
using Microsoft.Owin.Extensions;
using Owin;

namespace Auth0.Owin.Jwt
{
    /// <summary>
    /// Extension methods provided by the Auth0 JWT bearer token middleware.
    /// </summary>
    public static class Auth0JwtBearerAuthenticationExtensions
    {
        /// <summary>
        /// Adds JWT bearer token middleware to your web application pipeline.
        /// </summary>
        /// <param name="app">The IAppBuilder passed to your configuration method.</param>
        /// <param name="options">An options class that controls the middleware behavior.</param>
        /// <returns>The original app parameter.</returns>
        public static IAppBuilder UseAuth0JwtBearerAuthentication(this IAppBuilder app, Auth0JwtBearerAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            
            app.Use(typeof(Auth0JwtBearerAuthenticationMiddleware), app, options);
            app.UseStageMarker(PipelineStage.Authenticate);
            return app;
        }

        public static IAppBuilder UseAuth0JwtBearerAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return
                app.UseAuth0JwtBearerAuthentication(
                    new Auth0JwtBearerAuthenticationOptions(clientId: clientId, clientSecret: clientSecret));
        }
    }
}