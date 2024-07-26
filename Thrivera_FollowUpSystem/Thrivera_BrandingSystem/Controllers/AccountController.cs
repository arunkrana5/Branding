using Business;
using Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace Thrivera_BrandingSystem.Controllers
{
    public class AccountController : ApiController
    {
        [HttpPost]        
        public IHttpActionResult SaveVendorDetails(VendorDetailsRQ modal)
        {
            Response<bool> Result = new Response<bool>();
            Result = VendorBusiness.AddVendorDetails(modal);
            return Ok(Result);
        }
        public IHttpActionResult SaveClientDetails(ClientDetailsRQ modal)
        {
            Response<bool> Result = new Response<bool>();
            Result = ClientBusiness.AddClientDetails(modal);
            return Ok(Result);
        }
    }
}
