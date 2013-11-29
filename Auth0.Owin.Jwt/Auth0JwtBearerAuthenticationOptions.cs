using Microsoft.Owin.Security;

namespace Auth0.Owin.Jwt
{
    public class Auth0JwtBearerAuthenticationOptions : AuthenticationOptions
    {
        public Auth0JwtBearerAuthenticationOptions(string issuer = "https://login.auth0.com/", string clientId = null, string clientSecret = null, AuthenticationMode authenticationMode = AuthenticationMode.Active, string authenticationType = "Bearer")
            : base(authenticationType)
        {
            Issuer = issuer;
            Audience = clientId;
            SymmetricKey = clientSecret;
            AuthenticationMode = authenticationMode;
            AuthenticationType = authenticationType;
        }

        /// <summary>
        /// The Issuer of the JWT token - grab a token (https://docs.auth0.com/protocols) and use https://developers.google.com/commerce/wallet/digital/docs/jwtdecoder to see the issuer
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The Client Id from your Auth0 Application
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// The Client Secret from your Auth0 Application
        /// </summary>
        public string SymmetricKey { get; set; }
    }
}