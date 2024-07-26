using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace ApiServices.Authorization
{
    public class ApiAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        //IAccountsHelper Account = new AccountsModel();
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }
        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            var data = await context.Request.ReadFormAsync();            
            string Login_Type = data.Where(x => x.Key == "Login_Type").Select(x => x.Value).FirstOrDefault()[0];
            string IPAddress = data.Where(x => x.Key == "IPAddress").Select(x => x.Value).FirstOrDefault()[0];

            //AdminUser.Details Results = new AdminUser.Details();
            //Results = Account.GetLoginWithToken(context.UserName, context.Password, SessionID, IPAddress);
            //if (Results != null && Results.LoginID > 0)
            //{
            //    //identity.AddClaim(new Claim(ClaimTypes.Role, Results.RoleID.ToString()));
            //    //identity.AddClaim(new Claim("UserID", Results.UserID));
            //    //identity.AddClaim(new Claim("LoginID", Results.LoginID.ToString()));
            //    //identity.AddClaim(new Claim(ClaimTypes.Name, Results.UserID));
            //    //identity.AddClaim(new Claim("SessionID", SessionID));

            //    //context.Validated(identity);
            //    var props = new AuthenticationProperties(new Dictionary<string, string>
            //    {
            //        {
            //            "client_id", (context.ClientId == null) ? string.Empty : context.ClientId
            //        },
            //        {
            //            "userName", context.UserName
            //        },
            //        {
            //            "userDetails",JsonConvert.SerializeObject(Results)
            //        }
            //    }) ;
                
            //    var ticket = new AuthenticationTicket(identity, props);
            //    context.Validated(ticket);
            //}
            //else
            //{
            //    context.SetError("invalid_grant", "Provided username and password is incorrect");
            //    return;
            //}
        }
    }
}