using Infrastructure;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Database
{
    public class ClientSP
    {
       static string ConnectionStrings = ConfigurationManager.ConnectionStrings["connectionstring"].ConnectionString.ToString();
        public static Response<bool> AddClientDetails(ClientDetailsRQ modal)
        {
            Response<bool> Result = new Response<bool>();
            using (SqlConnection con = new SqlConnection(ConnectionStrings))
            {
                try
                {
                    con.Open();
                    using (SqlCommand command = new SqlCommand("spu_AddClientDetails", con))
                    {
                        SqlDataAdapter da = new SqlDataAdapter();
                        command.CommandType = CommandType.StoredProcedure;
                        command.Parameters.Add("@ClientID", SqlDbType.Int).Value = modal.ClientID;                       
                        command.Parameters.Add("@UserID", SqlDbType.VarChar).Value =modal.UserID;
                        command.Parameters.Add("@Password", SqlDbType.VarChar).Value = modal.Password;
                        command.Parameters.Add("@Name", SqlDbType.Int).Value = modal.Name;
                        command.Parameters.Add("@CompanyName", SqlDbType.Int).Value = modal.CompanyName;
                        command.Parameters.Add("@Mobile", SqlDbType.Int).Value = modal.Mobile;
                        command.Parameters.Add("@Email", SqlDbType.Int).Value = modal.Email;
                        command.Parameters.Add("@GSTNo", SqlDbType.Int).Value = modal.GSTNo;
                        command.Parameters.Add("@PanNo", SqlDbType.Int).Value = modal.PanNo;
                        command.Parameters.Add("@IsActive", SqlDbType.Int).Value = modal.IsActive;
                        command.Parameters.Add("@Priority", SqlDbType.Int).Value = modal.Priority ?? 0;
                        command.Parameters.Add("@createdby", SqlDbType.Int).Value = modal.LoginID;
                        command.Parameters.Add("@IPAddress", SqlDbType.VarChar).Value = modal.IPAddress;
                        command.CommandTimeout = 0;
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {                               
                                if (Convert.ToInt32(reader["Status"]) > 0)
                                {
                                    Result.Data = true;
                                    Result.TransactoinStatus = new Transaction()
                                    {
                                        IsSuccess = true,
                                        Error = new Error()
                                    };

                                }
                                else
                                {
                                    Result.Data = false;
                                    Result.TransactoinStatus = new Transaction()
                                    {
                                        IsSuccess = false,
                                        Error = new Error()
                                        {
                                            Code = Convert.ToInt32(reader["Status"]),
                                            Description = reader["Message"].ToString()
                                }
                                    };
                                }
                            }
                        }

                    }
                    con.Close();
                }
                catch (Exception ex)
                {
                    con.Close();                   
                    Result.Data = false;
                    Result.TransactoinStatus = new Transaction()
                    {
                        IsSuccess = false,
                        Error = new Error()
                        {
                            Code =-1,
                            Description = ex.Message.ToString()
                        }
                    };
                }
            }
            return Result;
        }
    }
}
