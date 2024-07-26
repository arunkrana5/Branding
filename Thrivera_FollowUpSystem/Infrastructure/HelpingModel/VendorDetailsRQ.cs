using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure
{
    public class VendorDetailsRQ
    {        
        public long VendorID { get; set; }        
        public string UserID { get; set; }
        public string Password { get; set; }
        public string Name { get; set; }
        public string CompanyName { get; set; }
        public string Mobile { get; set; }
        public string Email { get; set; }
        public string GSTNo { get; set; }
        public string PanNo { get; set; }
        public bool IsActive { get; set; }
        public int? Priority { get; set; }
        public long LoginID { get; set; }
        public string IPAddress { get; set; }
    }
}
