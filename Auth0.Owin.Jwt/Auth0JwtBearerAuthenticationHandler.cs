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
        readonly ILogger _logger;

        public Auth0JwtBearerAuthenticationHandler(ILogger logger)
        {
            _logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
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

                    return Task.FromResult(new AuthenticationTicket(claimsIdentityFromToken, new AuthenticationProperties()));
                }
                catch (JWT.SignatureVerificationException ex)
                {
                    if (_logger != null)
                        _logger.WriteError("SignatureVerificationException", ex);
                    return Task.FromResult<AuthenticationTicket>(null);
                }
                catch (JsonWebToken.TokenValidationException ex)
                {
                    if (_logger != null)
                        _logger.WriteError("TokenValidationException", ex);
                    return Task.FromResult<AuthenticationTicket>(null);
                }
                catch (Exception ex)
                {
                    if (_logger != null)
                        _logger.WriteError("Exception", ex); 
                    return Task.FromResult<AuthenticationTicket>(null);
                }
            }
            return Task.FromResult<AuthenticationTicket>(null);
        }

        private static bool TryRetrieveToken(IOwinRequest request, out string token)
        {
            token = null;
            string[] authzHeaders;

            if (request.Headers.TryGetValue("Authorization", out authzHeaders) && authzHeaders.Count() == 1)
            {
                // Remove the bearer token scheme prefix and return the rest as ACS token  
                var bearerToken = authzHeaders.ElementAt(0);
                const string bearerPrefix = "Bearer ";
                token = bearerToken.StartsWith(bearerPrefix) ? bearerToken.Substring(bearerPrefix.Length) : bearerToken;
                return true;
            }

            if (request.Query.Count(q => q.Key == "id_token") == 1)
            {
                token = request.Query.Single(q => q.Key == "id_token").Value.First();
                return true;
            }

            // Fail if no Authorization header or more than one Authorization headers  
            // are found in the HTTP request  
            return false;
        }
    }
}