using Database;
using Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Business
{
    public class ClientBusiness
    {
        public static Response<bool> AddClientDetails(ClientDetailsRQ modal)
        {
            Response<bool> Result = new Response<bool>();
            Result = ClientSP.AddClientDetails(modal);
            return Result;
        }
    }
}
