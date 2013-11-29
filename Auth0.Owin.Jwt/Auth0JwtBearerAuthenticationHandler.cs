using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Auth0.Owin.Jwt
{
    public class Auth0JwtBearerAuthenticationHandler : AuthenticationHandler<Auth0JwtBearerAuthenticationOptions>
    {
        readonly ILogger logger;

        public Auth0JwtBearerAuthenticationHandler(ILogger logger)
        {
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            string token;

            if (TryRetrieveToken(Request, out token))
            {
                try
                {
                    var secret = Options.SymmetricKey.Replace('-', '+').Replace('_', '/');

                    var claimsIdentityFromToken = JsonWebToken.ValidateToken(
                        token,
                        secret,
                        audience: Options.Audience,
                        checkExpiration: true,
                        issuer: Options.Issuer);

                    return new AuthenticationTicket(claimsIdentityFromToken, new AuthenticationProperties());

                }
                catch (JWT.SignatureVerificationException ex)
                {
                    return null;
                }
                catch (JsonWebToken.TokenValidationException ex)
                {
                    return null;
                }
                catch (Exception ex)
                {
                    return null;
                }
            }
            return null;
        }

        private static bool TryRetrieveToken(IOwinRequest request, out string token)
        {
            token = null;
            string[] authzHeaders;

            if (!request.Headers.TryGetValue("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                // Fail if no Authorization header or more than one Authorization headers  
                // are found in the HTTP request  
                return false;
            }

            // Remove the bearer token scheme prefix and return the rest as ACS token  
            var bearerToken = authzHeaders.ElementAt(0);
            const string bearerPrefix = "Bearer ";
            token = bearerToken.StartsWith(bearerPrefix) ? bearerToken.Substring(bearerPrefix.Length) : bearerToken;

            return true;
        }
    }
}