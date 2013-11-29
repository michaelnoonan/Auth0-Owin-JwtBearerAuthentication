using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Auth0.Owin.Jwt
{
    public class Auth0JwtBearerAuthenticationMiddleware : AuthenticationMiddleware<Auth0JwtBearerAuthenticationOptions>
    {
        private readonly ILogger logger;

        public Auth0JwtBearerAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            Auth0JwtBearerAuthenticationOptions options)
            : base(next, options)
        {
            logger = app.CreateLogger<Auth0JwtBearerAuthenticationMiddleware>();
        }

        

        protected override AuthenticationHandler<Auth0JwtBearerAuthenticationOptions> CreateHandler()
        {
            return new Auth0JwtBearerAuthenticationHandler(logger);
        }
    }
}