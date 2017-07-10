using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;

using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.Configuration;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Thinktecture.IdentityModel.Tokens;

namespace JsonWebTokensWebApi.Format
{
    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        

        private readonly string _issuer = string.Empty;

        public CustomJwtFormat(string issuer)
        {
            _issuer = issuer;
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }


            //Audience key was provided in GrantResourceOwnerCredentials()
            string audienceId = data.Properties.Dictionary.ContainsKey(Constants.ClientId) ? data.Properties.Dictionary[Constants.ClientId] : null;

            if (string.IsNullOrWhiteSpace(audienceId))
                throw new InvalidOperationException("AuthenticationTicket Properties does not include audience");


            string symmetricKeyAsBase64 = WebConfigurationManager.AppSettings["SymmetricKey"];

            var keyByteArray = TextEncodings.Base64Url.Decode(symmetricKeyAsBase64);

            var signingKey = new HmacSigningCredentials(keyByteArray);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;

            var token = new JwtSecurityToken(_issuer, audienceId, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingKey);

            var handler = new JwtSecurityTokenHandler();

            var jwt = handler.WriteToken(token);

            return jwt;
        }


        public AuthenticationTicket Unprotect(string protectedText)
        {
            var handler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = handler.ReadToken(protectedText);
            var audienceId = ((JwtSecurityToken)securityToken).Claims.First(x => x.Type == Constants.ClientId).Value;
            
            string symmetricKeyAsBase64 = WebConfigurationManager.AppSettings["SymmetricKey"];
            var keyByteArray = TextEncodings.Base64Url.Decode(symmetricKeyAsBase64);
            var securityKey = new InMemorySymmetricSecurityKey(keyByteArray);

            var validationParameters = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateAudience = true,
                ValidAudience = audienceId,
                ValidateIssuer = true,
                ValidIssuer = _issuer
            };

            SecurityToken validatedToken;
            ClaimsPrincipal principal = null;
            try
            {
                principal = handler.ValidateToken(protectedText, validationParameters, out validatedToken);
            }
            catch (Exception ex)
            {
                return null;
            }

            return new AuthenticationTicket(principal.Identities.First(), new AuthenticationProperties
            {
                IssuedUtc = validatedToken.ValidFrom,
                ExpiresUtc = validatedToken.ValidTo
            });
        }
    }
}