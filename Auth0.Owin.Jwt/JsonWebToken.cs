using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Script.Serialization;

namespace Auth0.Owin.Jwt
{
    /// <summary>
    /// Shamelessly modified from https://github.com/auth0/webapi-jsonwebtoken/blob/master/content/App_Start/JsonWebToken.cs.pp
    /// </summary>
    public static class JsonWebToken
    {
        const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
        const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
        const string ActorClaimType = "http://schemas.xmlsoap.org/ws/2009/09/identity/claims/actor";
        const string DefaultIssuer = "LOCAL AUTHORITY";
        const string StringClaimValueType = "http://www.w3.org/2001/XMLSchema#string";

        // sort claim types by relevance
        static readonly string[] ClaimTypesForUserName = {"name", "email", "user_id", "sub"};
        static readonly string[] ClaimsToExclude = {"iss", "sub", "aud", "exp", "iat", "identities"};

        static readonly JavaScriptSerializer JsonSerializer = new JavaScriptSerializer();

        public static ClaimsIdentity ValidateToken(string token, string secretKey, string audience = null,
            bool checkExpiration = false, string issuer = null)
        {
            var payloadJson = JWT.JsonWebToken.Decode(token, Convert.FromBase64String(secretKey), verify: true);
            var payloadData = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

            // audience check
            object aud;
            if (!string.IsNullOrEmpty(audience) && payloadData.TryGetValue("aud", out aud))
            {
                if (!aud.ToString().Equals(audience, StringComparison.Ordinal))
                {
                    throw new TokenValidationException(string.Format(
                        "Audience mismatch. Expected: '{0}' and got: '{1}'", audience, aud));
                }
            }

            // expiration check
            object exp;
            if (checkExpiration && payloadData.TryGetValue("exp", out exp))
            {
                DateTime validTo = FromUnixTime(long.Parse(exp.ToString()));
                if (DateTime.Compare(validTo, DateTime.UtcNow) <= 0)
                {
                    throw new TokenValidationException(
                        string.Format("Token is expired. Expiration: '{0}'. Current: '{1}'", validTo, DateTime.UtcNow));
                }
            }

            // issuer check
            object iss;
            if (payloadData.TryGetValue("iss", out iss))
            {
                if (!string.IsNullOrEmpty(issuer))
                {
                    if (!iss.ToString().Equals(issuer, StringComparison.Ordinal))
                    {
                        throw new TokenValidationException(
                            string.Format("Token issuer mismatch. Expected: '{0}' and got: '{1}'", issuer, iss));
                    }
                }
                else
                {
                    // if issuer is not specified, set issuer with jwt[iss]
                    issuer = iss.ToString();
                }
            }

            return ClaimsIdentityFromJwt(payloadData, issuer);
        }

        static List<Claim> ClaimsFromJwt(IDictionary<string, object> jwtData, string issuer)
        {
            var list = new List<Claim>();
            issuer = issuer ?? DefaultIssuer;

            foreach (KeyValuePair<string, object> pair in jwtData)
            {
                var claimType = pair.Key;
                var source = pair.Value as ArrayList;

                if (source != null)
                {
                    foreach (var item in source)
                    {
                        list.Add(new Claim(claimType, item.ToString(), StringClaimValueType, issuer, issuer));
                    }

                    continue;
                }

                var claim = new Claim(claimType, pair.Value.ToString(), StringClaimValueType, issuer, issuer);
                list.Add(claim);
            }

            // set claim for user name
            for (int i = 0; i < ClaimTypesForUserName.Length; i++)
            {
                if (list.Any(c => c.Type == ClaimTypesForUserName[i]))
                {
                    var nameClaim = new Claim(NameClaimType, list.First(c => c.Type == ClaimTypesForUserName[i]).Value,
                        StringClaimValueType, issuer, issuer);
                    list.Add(nameClaim);
                    break;
                }
            }

            // dont include specific jwt claims
            return list.Where(c => !ClaimsToExclude.Any(t => t == c.Type)).ToList();
        }

        static ClaimsIdentity ClaimsIdentityFromJwt(IDictionary<string, object> jwtData, string issuer)
        {
            var subject = new ClaimsIdentity("Federation", NameClaimType, RoleClaimType);
            var claims = ClaimsFromJwt(jwtData, issuer);

            foreach (Claim claim in claims)
            {
                var type = claim.Type;
                if (type == ActorClaimType)
                {
                    if (subject.Actor != null)
                    {
                        throw new InvalidOperationException(string.Format(
                            "Jwt10401: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'",
                            new object[] {"actor", claim.Value}));
                    }

                    var claim2 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, subject);
                    subject.AddClaim(claim2);

                    continue;
                }

                var claim3 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, subject);
                subject.AddClaim(claim3);
            }

            return subject;
        }

        static DateTime FromUnixTime(long unixTime)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(unixTime);
        }

        public class TokenValidationException : Exception
        {
            public TokenValidationException(string message)
                : base(message)
            {
            }
        }
    }
}