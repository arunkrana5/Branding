using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Common
{
    public class ClsCommon
    {
        public static string GetIPAddress()
        {
            return HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
        }
        public static string EnsureString(string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                str = "";
            }
            return str.Replace("'", "''").Replace("\"", "" + "").Trim();
        }

        public static string Encrypt(string clearText)
        {
            try
            {
                if (!string.IsNullOrEmpty(clearText))
                {
                    string EncryptionKey = "RAISOFT";
                    byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
                    using (Aes encryptor = Aes.Create())
                    {
                        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                        encryptor.Key = pdb.GetBytes(32);
                        encryptor.IV = pdb.GetBytes(16);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(clearBytes, 0, clearBytes.Length);
                                cs.Close();
                            }
                            clearText = Convert.ToBase64String(ms.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
               
            }
            return clearText;
        }
        public static string Decrypt(string cipherText)
        {
            try
            {
                if (!string.IsNullOrEmpty(cipherText))
                {

                    string EncryptionKey = "RAISOFT";
                    cipherText = cipherText.Replace(" ", "+");
                    byte[] cipherBytes = Convert.FromBase64String(cipherText);
                    using (Aes encryptor = Aes.Create())
                    {
                        Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                        encryptor.Key = pdb.GetBytes(32);
                        encryptor.IV = pdb.GetBytes(16);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(cipherBytes, 0, cipherBytes.Length);
                                cs.Close();
                            }
                            cipherText = Encoding.Unicode.GetString(ms.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                
            }
            return cipherText;
        }

        public static string ConnectionString()
        {
            return ConfigurationManager.ConnectionStrings["connectionstring"].ConnectionString.ToString();
        }
    }
}
