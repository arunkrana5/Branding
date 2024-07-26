using Database;
using Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Business
{
    public class VendorBusiness
    {
        public static Response<bool> AddVendorDetails(VendorDetailsRQ modal)
        {
            Response<bool> Result = new Response<bool>();
            Result = VendorSP.AddVendorDetailsBySP(modal);
            return Result;
        }
        }
}
