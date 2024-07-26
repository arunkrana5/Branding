using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure
{
   public class Response<T>
    {
        public Transaction TransactoinStatus { get; set; }
        public T Data { get; set; }
    }
    public class Transaction
    {
        public bool IsSuccess { get; set; }
        public Error Error { get; set; }
    }
    public class Error
    {
        public int Code{ get; set; }
        public string Type{ get; set; }
        public string Description { get; set; }
    }
}
