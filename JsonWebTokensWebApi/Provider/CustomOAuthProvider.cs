using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JsonWebTokensWebApi.Domain;
using JsonWebTokensWebApi.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace JsonWebTokensWebApi.Provider
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly hPayDomain _hPayDomain;
        private string _userFullName;
        private string _emailId;

        public CustomOAuthProvider()
        {
            _hPayDomain = new hPayDomain();
        }

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            //string clientId = string.Empty;
            //string clientSecret = string.Empty;

            //if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            //{
            //    context.TryGetFormCredentials(out clientId, out clientSecret);
            //}

            //context.Validated();
            //return Task.FromResult<object>(null);


            string clientId;
            string clientSecret;

            context.TryGetFormCredentials(out clientId, out clientSecret);


            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "ClientId should be sent.");
            }

            Client client = _hPayDomain.GetClient(context.ClientId);

            if (client != null)
            {
                if (client.Secret != clientSecret)
                {
                    context.SetError("invalid_clientSecret", "Client secret is invalid.");
                }

                if (!client.Active)
                {
                    context.SetError("invalid_clientId", "Client is inactive.");
                }

                context.OwinContext.Set<string>(Constants.ClientRefreshTokenLifeTime, client.RefreshTokenLifeTime.ToString());

                context.Validated();
            }
            else
            {
                context.SetError("invalid_clientId", $"Client '{context.ClientId}' is not registered in the system.");
            }
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext oAuthGrantResourceOwnerCredentialsContext)
        {
            User hPayUser = _hPayDomain.AuthenticateUser(oAuthGrantResourceOwnerCredentialsContext.UserName, oAuthGrantResourceOwnerCredentialsContext.Password);




            if (hPayUser != null)
            {
                _userFullName = hPayUser.UserFirstName + " " + hPayUser.UserLastName;
                _emailId = hPayUser.EmailId;

                IList<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Role, "provider"),
                    new Claim(ClaimTypes.Name, _userFullName),
                    new Claim(Constants.Username, _emailId)
                };

                ClaimsIdentity identity = new ClaimsIdentity(claims, oAuthGrantResourceOwnerCredentialsContext.Options.AuthenticationType);

                IDictionary<string, string> authenticationPropertiesDictionary = new Dictionary<string, string>();
                authenticationPropertiesDictionary.Add(Constants.ClientId, oAuthGrantResourceOwnerCredentialsContext.ClientId ?? string.Empty);
                //authenticationPropertiesDictionary.Add(Constants.Audience, oAuthGrantResourceOwnerCredentialsContext.ClientId ?? string.Empty);
                authenticationPropertiesDictionary.Add(Constants.Username, oAuthGrantResourceOwnerCredentialsContext.UserName);
                authenticationPropertiesDictionary.Add(Constants.UserFullName, hPayUser.UserFirstName + " " + hPayUser.UserLastName);
                authenticationPropertiesDictionary.Add("MyKey", "MyValue");


                //Adds authentication properties, if you want your client to be able to read extended properties
                AuthenticationProperties authenticationProperties = new AuthenticationProperties(authenticationPropertiesDictionary);

                AuthenticationTicket ticket = new AuthenticationTicket(identity, authenticationProperties);

                //The token generation happens behind the scenes when we call  "oAuthGrantResourceOwnerCredentialsContext.Validated(ticket);"
                oAuthGrantResourceOwnerCredentialsContext.Validated(ticket);

            }
            else
            {
                oAuthGrantResourceOwnerCredentialsContext.SetError("invalid_grant", "The user name or password is incorrect");

            }


        }



        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext oAuthGrantRefreshTokenContext)
        {
            var originalClient = oAuthGrantRefreshTokenContext.Ticket.Properties.Dictionary[Constants.ClientId];
            var userName = oAuthGrantRefreshTokenContext.Ticket.Properties.Dictionary[Constants.Username];
            var currentClient = oAuthGrantRefreshTokenContext.ClientId;

            User hPayUser = _hPayDomain.GetUser(userName);

            var newIdentity = new ClaimsIdentity(oAuthGrantRefreshTokenContext.Ticket.Identity);
            var newClaim = newIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            if (newClaim != null)
            {
                newIdentity.RemoveClaim(newClaim);
            }

            newIdentity.AddClaim(new Claim(ClaimTypes.Name, hPayUser.UserFirstName + " " + hPayUser.UserLastName));

            if (originalClient != currentClient)
            {
                oAuthGrantRefreshTokenContext.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
            }

            oAuthGrantRefreshTokenContext.Validated(newIdentity);

        }




        // Add additional parameter to return with response
        public override Task TokenEndpoint(OAuthTokenEndpointContext oAuthTokenEndpointContext)
        {
            // Add authentication properties via iterate which is added as a part of GrantResourceOwnerCredentials()
            foreach (KeyValuePair<string, string> property in oAuthTokenEndpointContext.Properties.Dictionary)
            {
                oAuthTokenEndpointContext.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            oAuthTokenEndpointContext.AdditionalResponseParameters.Add("TestParam1", "Value1");
            oAuthTokenEndpointContext.AdditionalResponseParameters.Add("TestParam2", "Value2");

            return Task.FromResult<object>(null);
        }
    }
}