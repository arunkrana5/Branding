using Database;
using Databases.Procedures;
using Infrastructure;
using Infrastructure.Configration;
using Infrastructure.HelpingModel;
using Infrastructure.HelpingModel.API;
using Infrastructure.Interfaces;
using Logger;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Caching;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Serialization;
using TimeZoneConverter;
using TravelAPISolution.Database;
using Mongo = Infrastructure.NoSQL;
namespace Common
{
    public class Utility
    {
        private static bool IsLoadedApplication = false;
        private static object syncPoolRoot = new Object();
        public static TextInfo textInfo = new CultureInfo("en-US", false).TextInfo;
        public static ILoggingService Logger = (ILoggingService)LoggingService.GetLoggingService();
        public static IDatabaseService DatabaseService = (IDatabaseService)new DatabaseService();
        public static IMongoDBRepository MongoInstance = null;
        public static ICachingProvider CachingProvider = null;
        public static Settings Settings = null;
        public static PortalSettings Portal = null;
        public static Modules Module = null;
        public static string UTCDateStringFormat = "dd-MM-yyyy HH:mm:ss UTC";
        public static void LoadApplication()
        {
            try
            {
                Utility.Logger.Info("APPLICATION START LOADING");
                Common.CalendarDropdown.GetDashSearchDropdown(null);
                if (!IsLoadedApplication)
                {
                    lock (syncPoolRoot)
                    {
                        if (!IsLoadedApplication)
                        {
                            Settings = LoadConfigSettings();
                            if (Settings != null)
                            {
                                CachingProvider = (ICachingProvider)new MemcachedCachingProvider(Settings.MemCache.MemCacheServerIP, Settings.MemCache.MemCacheServerPort, null, null, null);
                                MongoInstance = new MongoDBRepository(Settings.MongoDB.Connection, Settings.MongoDB.Database);

                                List<Task> lstTasks = new List<Task>
                                {
                                   Task.Factory.StartNew(()=>Portal= PortalSetting.GetPortalSetting(Settings.DatabaseConnection.AkountoDB)),
                                   Task.Factory.StartNew(()=>Module=GetModuleAction()),
                                };
                                Task.WaitAll(lstTasks.ToArray());
                                IsLoadedApplication = true;
                                Task.Factory.StartNew(() => PushNotifications.LoadApplication());
                            }

                        }
                    }
                }
                Logger.Info("APPLICATION END LOADING");
            }
            catch (Exception ex)
            {
                Logger.Error("APPLICATION START ISSUE:EXCEPTION|" + ex.ToString());
            }
        }

        public static DateTime GetUTCDate(string _date)
        {
            return DateTime.ParseExact(_date, UTCDateStringFormat, CultureInfo.CurrentCulture, DateTimeStyles.AdjustToUniversal);
        }
        /// <summary>
        /// Load configration settings at time appliction repool
        /// </summary>
        /// <returns></returns>
        private static Settings LoadConfigSettings()
        {
            Settings settings = null;
            try
            {
                Utility.Logger.Info("Common.Utility.LoadConfigSettings:Begin");
                string path = Path.Combine(HttpRuntime.AppDomainAppPath, string.Format("Configrations\Settings.config"));
                StreamReader reader = new StreamReader(path);
                settings = Utility.GetFileDeserialize<Settings>(reader);
                Utility.Logger.Info("Common.Utility.LoadConfigSettings:Load Data Successfully.");
            }
            catch (Exception ex)
            {
                Logger.Error("LoadConfigSettings:EXCEPTION|" + ex.ToString());
            }
            return settings;
        }


        /// <summary>
        /// Deserialize stream
        /// </summary>
        /// <typeparam name="T">Generic object</typeparam>
        /// <param name="reader">StreamReader</param>
        /// <returns></returns>
        public static T GetFileDeserialize<T>(StreamReader reader)
        {
            T response = default(T);
            try
            {
                XmlSerializer deserializer = new XmlSerializer(typeof(T));
                object obj = deserializer.Deserialize(reader);
                response = (T)obj;
                reader.Close();
            }
            catch (Exception ex)
            {
                Utility.Logger.Error("Business.Utility.GetFileDeserialize<T>:" + ex.ToString());
            }
            return response;
        }


        /// <summary>
        /// Make sentense proper case or title case
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public static string GetTitleCase(string text)
        {
            return textInfo.ToTitleCase(text);
        }

        private const int PBKDF2IterCount = 1000;
        private const int PBKDF2SubkeyLength = 256 / 8;
        private const int SaltSize = 128 / 8;
        public static string HashPassword(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            byte[] salt;
            byte[] subkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, SaltSize, PBKDF2IterCount))
            {
                salt = deriveBytes.Salt;
                subkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }

            var outputBytes = new byte[1 + SaltSize + PBKDF2SubkeyLength];
            Buffer.BlockCopy(salt, 0, outputBytes, 1, SaltSize);
            Buffer.BlockCopy(subkey, 0, outputBytes, 1 + SaltSize, PBKDF2SubkeyLength);
            return Convert.ToBase64String(outputBytes);
        }
        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            if (hashedPassword == null)
            {
                return false;
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var hashedPasswordBytes = Convert.FromBase64String(hashedPassword);

            if (hashedPasswordBytes.Length != (1 + SaltSize + PBKDF2SubkeyLength) || hashedPasswordBytes[0] != 0x00)
            {
                return false;
            }

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(hashedPasswordBytes, 1, salt, 0, SaltSize);
            var storedSubkey = new byte[PBKDF2SubkeyLength];
            Buffer.BlockCopy(hashedPasswordBytes, 1 + SaltSize, storedSubkey, 0, PBKDF2SubkeyLength);

            byte[] generatedSubkey;
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, PBKDF2IterCount))
            {
                generatedSubkey = deriveBytes.GetBytes(PBKDF2SubkeyLength);
            }
            return ByteArraysEqual(storedSubkey, generatedSubkey);
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }

        public static string GetRole(IList<string> roles)
        {
            string response = string.Empty;
            try
            {
                if (roles != null && roles.Count > 0)
                {
                    response = roles[0];
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error("Utility.GetRole:" + ex.ToString());
            }
            return response;
        }

        /// <summary>
        /// Get Enum Description
        /// </summary>
        /// <param name="enumValue">Enum</param>
        /// <returns>string</returns>
        public static string GetEnumDescription(Enum enumValue)
        {
            string enumDesc = string.Empty;

            FieldInfo fieldInfo = enumValue.GetType().GetField(enumValue.ToString());

            if (fieldInfo != null)
            {
                object[] attrs = fieldInfo.GetCustomAttributes(typeof(DescriptionAttribute), true);
                if (attrs != null && attrs.Length > 0)
                    return ((DescriptionAttribute)attrs[0]).Description;
            }

            return enumDesc;
        }

        public static Transaction GetTransactionStatus(WebTransactionStatus _status)
        {
            Transaction status = null;
            try
            {
                switch (_status)
                {
                    case WebTransactionStatus.Success:
                        status = new Transaction()
                        {
                            IsSuccess = true
                        };
                        break;
                    case WebTransactionStatus.BadRequest:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = (int)WebTransactionStatus.BadRequest,
                                Description = GetEnumDescription(WebTransactionStatus.BadRequest),
                                Type = WebTransactionStatus.BadRequest.ToString()
                            }
                        };
                        break;
                    case WebTransactionStatus.Unauthorized:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.Unauthorized),
                                Description = GetEnumDescription(WebTransactionStatus.Unauthorized),
                                Type = WebTransactionStatus.Unauthorized.ToString()
                            }
                        };
                        break;
                    case WebTransactionStatus.Conflict:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.Conflict),
                                Description = GetEnumDescription(WebTransactionStatus.Conflict),
                                Type = WebTransactionStatus.Conflict.ToString()
                            }
                        };
                        break;
                    case WebTransactionStatus.InternalServerError:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.InternalServerError),
                                Description = GetEnumDescription(WebTransactionStatus.InternalServerError),
                                Type = WebTransactionStatus.InternalServerError.ToString()
                            }
                        };
                        break;
                    case WebTransactionStatus.NotFound:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.NotFound),
                                Description = GetEnumDescription(WebTransactionStatus.NotFound),
                                Type = WebTransactionStatus.NotFound.ToString()
                            }
                        };
                        break;
                    case WebTransactionStatus.MailSendFailed:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.MailSendFailed),
                                Description = GetEnumDescription(WebTransactionStatus.MailSendFailed),
                                Type = WebTransactionStatus.MailSendFailed.ToString()
                            }
                        };
                        break;

                    case WebTransactionStatus.UserAlreadyExist:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.UserAlreadyExist),
                                Description = GetEnumDescription(WebTransactionStatus.UserAlreadyExist),
                                Type = WebTransactionStatus.UserAlreadyExist.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.EmailConfirmationRequired:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.EmailConfirmationRequired),
                                Description = GetEnumDescription(WebTransactionStatus.EmailConfirmationRequired),
                                Type = WebTransactionStatus.EmailConfirmationRequired.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.PasswordRequired:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.PasswordRequired),
                                Description = GetEnumDescription(WebTransactionStatus.PasswordRequired),
                                Type = WebTransactionStatus.PasswordRequired.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.EmailVerificationAlreadyDone:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.EmailVerificationAlreadyDone),
                                Description = GetEnumDescription(WebTransactionStatus.EmailVerificationAlreadyDone),
                                Type = WebTransactionStatus.EmailVerificationAlreadyDone.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.UserCannotDisassociateOurSelf:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.UserCannotDisassociateOurSelf),
                                Description = GetEnumDescription(WebTransactionStatus.UserCannotDisassociateOurSelf),
                                Type = WebTransactionStatus.UserCannotDisassociateOurSelf.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.EmailVerificationRequiredForPasswordReset:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.EmailVerificationRequiredForPasswordReset),
                                Description = GetEnumDescription(WebTransactionStatus.EmailVerificationRequiredForPasswordReset),
                                Type = WebTransactionStatus.EmailVerificationRequiredForPasswordReset.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.ConfirmPasswordNotMatched:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.ConfirmPasswordNotMatched),
                                Description = GetEnumDescription(WebTransactionStatus.ConfirmPasswordNotMatched),
                                Type = WebTransactionStatus.ConfirmPasswordNotMatched.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.InvalidToken:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.InvalidToken),
                                Description = GetEnumDescription(WebTransactionStatus.InvalidToken),
                                Type = WebTransactionStatus.InvalidToken.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.EmailNotFound:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.EmailNotFound),
                                Description = GetEnumDescription(WebTransactionStatus.EmailNotFound),
                                Type = WebTransactionStatus.EmailNotFound.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.UserNotFound:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.UserNotFound),
                                Description = GetEnumDescription(WebTransactionStatus.UserNotFound),
                                Type = WebTransactionStatus.UserNotFound.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.UserInvitationFailed:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.UserInvitationFailed),
                                Description = GetEnumDescription(WebTransactionStatus.UserInvitationFailed),
                                Type = WebTransactionStatus.UserInvitationFailed.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.InvalidProviderOrAccessToken:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.InvalidProviderOrAccessToken),
                                Description = GetEnumDescription(WebTransactionStatus.InvalidProviderOrAccessToken),
                                Type = WebTransactionStatus.InvalidProviderOrAccessToken.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.ExternalUserNotRegistered:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.ExternalUserNotRegistered),
                                Description = GetEnumDescription(WebTransactionStatus.ExternalUserNotRegistered),
                                Type = WebTransactionStatus.ExternalUserNotRegistered.ToString()

                            }
                        };
                        break;
                    case WebTransactionStatus.UserNotAssociatedWithBusiness:
                        status = new Transaction()
                        {
                            IsSuccess = false,
                            Error = new Error()
                            {
                                Code = ((int)WebTransactionStatus.UserNotAssociatedWithBusiness),
                                Description = GetEnumDescription(WebTransactionStatus.UserNotAssociatedWithBusiness),
                                Type = WebTransactionStatus.UserNotAssociatedWithBusiness.ToString()

                            }
                        };
                        break;
                    default:
                        status = new Transaction()
                        {
                            IsSuccess = true
                        };
                        break;
                }
            }
            catch (Exception ex)
            {

                Logger.Error("GetTransactionStatus:EXCEPTION|" + ex.ToString());
            }
            return status;
        }

        public static LoginUserClaim GetClaim(HttpRequestMessage Request)
        {
            LoginUserClaim response = null;
            try
            {
                if (Request != null)
                {
                    response = new LoginUserClaim();
                    int companyId = 0;
                    ClaimsPrincipal principal = Request.GetRequestContext().Principal as ClaimsPrincipal;
                    int.TryParse(principal.Claims.Where(c => c.Type == "CompanyId").Single().Value, out companyId);
                    response.UserName = principal.Claims.Where(c => c.Type == "UserName").Single().Value;
                    response.UserId = principal.Claims.Where(c => c.Type == "UserID").Single().Value;
                    response.CompanyId = companyId;
                    response.TimeZone = principal.Claims.Where(c => c.Type == "TimeZone").Single().Value;
                    response.Currency = principal.Claims.Where(c => c.Type == "BusinessCurrency").Single().Value;
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility.GetClaim:Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static DateTime GetDateTimeBasedOnTimeZone(DateTime _date, string _timeZone)
        {
            DateTime response = DateTime.UtcNow;
            try
            {
                if (!string.IsNullOrEmpty(_timeZone))
                {
                    TimeZoneInfo timeZone = TimeZoneInfo.FindSystemTimeZoneById(_timeZone);
                    response = TimeZoneInfo.ConvertTime(_date, timeZone);
                }
                else
                {
                    response = _date;
                }
            }
            catch (Exception ex)
            {
                response = _date;
                Utility.Logger.Error(string.Format("Utility.GetDateTimeBasedOnTimeZone:Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static Heads GetSubHeads()
        {
            Heads response = null;
            try
            {
                if (Utility.Portal.HeadSubs != null && Utility.Portal.HeadSubs.Count > 0)
                {
                    response = new Heads();
                    response.HeadTypes = Enum.GetNames(typeof(HeadType)).Skip(1).Select(o => new Head()
                    {
                        Id = (int)Enum.Parse(typeof(HeadType), o),
                        Name = o,
                        HeadSubTypes = Utility.Portal.HeadSubs.Where(c => c.HeadId == (int)Enum.Parse(typeof(HeadType), o)).Select(h => new HeadSubs()
                        {
                            Id = h.Id,
                            Name = h.Name
                        }).ToList()
                    }).ToList();
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility.GetSubHeads:Exception:{0}", ex.ToString()));
            }
            return response;
        }

        //public static DateTime ConvertTimeZone(DateTime dateTime, string timeInfo)
        //{
        //    var result = OlsonTimeZoneToTimeZoneInfo(timeInfo);
        //    if (result != null)
        //    {
        //        var finalTimeZone = TimeZoneInfo.FindSystemTimeZoneById(result);
        //        dateTime = (dateTime != null ? TimeZoneInfo.ConvertTimeFromUtc(dateTime != null ? dateTime : DateTime.UtcNow, finalTimeZone) : DateTime.UtcNow);
        //    }
        //    return dateTime;
        //}

        //public static bool isValidTimeZoneId(string timeZoneId)
        //{
        //    if (string.IsNullOrEmpty(timeZoneId) || string.IsNullOrWhiteSpace(timeZoneId))
        //        return false;

        //    ReadOnlyCollection<TimeZoneInfo> tz;
        //    tz = TimeZoneInfo.GetSystemTimeZones();

        //    return tz.Any(x => x.Id == timeZoneId);
        //}

        public static HeadType GetHeadBySubHeadId(int _headSubId)
        {
            HeadType response = HeadType.None;
            try
            {
                var subHead = Utility.Portal.HeadSubs.Where(o => o.Id == _headSubId).FirstOrDefault();
                if (subHead != null)
                {
                    response = (HeadType)subHead.HeadId;
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetHeadBySubHeadId|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static string GetSubHeadName(int _headSubId)
        {
            string response = string.Empty;
            try
            {
                var subHead = Utility.Portal.HeadSubs.Where(o => o.Id == _headSubId).FirstOrDefault();
                if (subHead != null)
                {
                    response = subHead.Name;
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetSubHeadName|Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static void AddErrorMongo(Log _log)
        {
            try
            {
                if (_log != null)
                {
                    Task.Factory.StartNew(() =>
                    {
                        Mongo.Logs log = new Mongo.Logs()
                        {
                            Level = _log.level,
                            Additional = _log.additional,
                            FileName = _log.filename,
                            LineNumber = _log.linenumber,
                            Message = _log.message,
                            TimeStamp = _log.timestamp
                        };
                        Utility.MongoInstance.Add<Mongo.Logs>(log);
                    });
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|AddErrorMongo|Exception:{0}", ex.ToString()));
            }
        }

        public static DateTime ConvertTimeToUtc(DateTime _zoneDateTime, string _timezone)
        {
            TimeZoneInfo timezone = TZConvert.GetTimeZoneInfo(_timezone);
            var dateTimeUnspec = DateTime.SpecifyKind(_zoneDateTime, DateTimeKind.Unspecified);
            return TimeZoneInfo.ConvertTimeToUtc(dateTimeUnspec, timezone);
        }
        public static int GetBaseUtcOffset(string _timezone)
        {
            try
            {
                return (int)TZConvert.GetTimeZoneInfo(_timezone).BaseUtcOffset.TotalMinutes;
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetTimezoneOffset|Exception:{0}", ex.ToString()));
            }
            return 0;
        }
        public static DateTime ConvertTimeFromUtc(DateTime _utcDate, string _destTimezone)
        {
            TimeZoneInfo timezone = TZConvert.GetTimeZoneInfo(_destTimezone);
            return TimeZoneInfo.ConvertTime(_utcDate, timezone);
        }
        public static string Encrypt(string _clearText, string _encryptionKey)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(_clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    _clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return _clearText;
        }
        public static string Decrypt(string _clearText, string _encryptionKey)
        {
            byte[] cipherBytes = Convert.FromBase64String(_clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(_encryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    _clearText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return _clearText;
        }


        // Convert an object to a byte array
        public static byte[] ObjectToByteArray(Object obj)
        {
            if (obj == null)
                return null;

            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);

            return ms.ToArray();
        }

        // Convert a byte array to an Object
        public static Object ByteArrayToObject(byte[] arrBytes)
        {
            MemoryStream memStream = new MemoryStream();
            BinaryFormatter binForm = new BinaryFormatter();
            memStream.Write(arrBytes, 0, arrBytes.Length);
            memStream.Seek(0, SeekOrigin.Begin);
            Object obj = (Object)binForm.Deserialize(memStream);

            return obj;
        }

        public static string GetCacheKey(string id)
        {
            return string.Format("{0}{1}", Utility.Settings.MemCache.IsLive ? "1" : "0", id).ToLower().Trim();
        }




        public static UserBusiness GetActiveCompany(HttpRequestMessage Request)
        {
            UserBusiness userBusiness = null;
            try
            {
                if (Request != null)
                {

                    int companyId = 0;
                    ClaimsPrincipal principal = Request.GetRequestContext().Principal as ClaimsPrincipal;
                    string xAuthoriseToken = Request.Headers.Contains("X-Company") ? Request.Headers.GetValues("X-Company").First().Trim().ToLower() : string.Empty;
                    if (!string.IsNullOrEmpty(xAuthoriseToken))
                    {
                        int.TryParse(xAuthoriseToken, out companyId);

                    }
                    string userId = principal.Claims.Where(c => c.Type == "UserID").FirstOrDefault().Value;
                    if (!string.IsNullOrEmpty(userId) && companyId > 0)
                    {
                        CacheUserBusiness cacheUserBusiness = null;
                        string strBusiness = string.Empty;
                        Utility.CachingProvider.Get<string>(GetCacheKey(userId), out strBusiness);
                        if (!string.IsNullOrEmpty(strBusiness))
                        {
                            cacheUserBusiness = JsonConvert.DeserializeObject<CacheUserBusiness>(strBusiness);
                            if (cacheUserBusiness != null)
                            {
                                userBusiness = cacheUserBusiness.UserBusinesses.Where<UserBusiness>(o => o.Id == companyId).FirstOrDefault<UserBusiness>();
                                if (userBusiness != null && companyId != cacheUserBusiness.ActiveCompanyId)
                                {
                                    Task.Factory.StartNew(() => SetActiveCompany(cacheUserBusiness, companyId, userId, false));
                                }
                            }
                            else
                            {
                                Utility.Logger.Error(string.Format("USER NOT FOUND IN CACHE | UserId:{0}, CompanyId:{1}", userId, companyId));
                            }
                        }
                        else
                        {
                            Utility.Logger.Error(string.Format("USER NOT FOUND IN CACHE | UserId:{0}, CompanyId:{1}", userId, companyId));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility.GetActiveCompany:Exception:{0}", ex.ToString()));
            }
            return userBusiness;
        }

        /// <summary>
        /// User's existing companies's current active
        /// </summary>
        /// <param name="_lstUserBusinesses"></param>
        /// <param name="_activeCompanyId"></param>
        /// <param name="_loginId"></param>
        /// <param name="IsInitilize"></param>
        public static void SetActiveCompany(CacheUserBusiness _cacheUserBusiness, int _activeCompanyId, string _loginId, bool _IsInitialze)
        {
            try
            {
                if (_IsInitialze)
                {
                    if (_cacheUserBusiness != null && _cacheUserBusiness.UserBusinesses != null)
                    {
                        _cacheUserBusiness.ActiveCompanyId = _activeCompanyId;
                        int minutes = Utility.Settings.UserExpiryInMinutes + 1;
                        _cacheUserBusiness.ExpityUTC = DateTime.UtcNow.AddMinutes(minutes).ToString(Utility.UTCDateStringFormat);
                        Utility.CachingProvider.Set<string>(Utility.GetCacheKey(_loginId), JsonConvert.SerializeObject(_cacheUserBusiness), CacheItemPriority.Default, minutes);
                    }
                }
                else
                {
                    if (_cacheUserBusiness != null && _cacheUserBusiness.UserBusinesses != null)
                    {
                        _cacheUserBusiness.ActiveCompanyId = _activeCompanyId;
                        int minutes = Convert.ToInt32((Utility.GetUTCDate(_cacheUserBusiness.ExpityUTC) - DateTime.UtcNow).TotalMinutes);
                        Utility.CachingProvider.Set<string>(Utility.GetCacheKey(_loginId), JsonConvert.SerializeObject(_cacheUserBusiness), CacheItemPriority.Default, minutes);
                    }
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Info(string.Format("CRITICAL ISSUE|SetActiveCompany|CompanyId:{0}", _activeCompanyId));
                Utility.Logger.Error(string.Format("Utility|SetActiveCompany|Exception:{0}", ex.ToString()));
            }
        }


        public static Response<UserInfo> GetUserCompanyies(string _loginId)
        {
            Response<UserInfo> response = null;
            try
            {
                CacheUserBusiness cacheUserBusiness = null;
                string strBusiness = string.Empty;
                Utility.CachingProvider.Get<string>(GetCacheKey(_loginId), out strBusiness);
                if (!string.IsNullOrEmpty(strBusiness))
                {
                    cacheUserBusiness = JsonConvert.DeserializeObject<CacheUserBusiness>(strBusiness);
                    if (cacheUserBusiness != null)
                    {
                        response = new Response<UserInfo>()
                        {
                            TransactionStatus = new Transaction() { IsSuccess = true },
                            Data = new UserInfo()
                            {
                                Business = cacheUserBusiness.UserBusinesses,
                                ActiveBusiness = cacheUserBusiness.UserBusinesses.Where<UserBusiness>(o => o.Id == cacheUserBusiness.ActiveCompanyId).FirstOrDefault<UserBusiness>()
                            }
                        };

                    }
                }

                if (response == null || (response != null && response.TransactionStatus == null) || (response != null && response.TransactionStatus != null && response.TransactionStatus.IsSuccess == false))
                {
                    response = new Response<UserInfo>()
                    {
                        TransactionStatus = new Transaction() { IsSuccess = false, Error = new Error() { Code = 404, Description = "User Company not found." } },
                        Data = new UserInfo()
                        {
                            Business = cacheUserBusiness.UserBusinesses,
                            ActiveBusiness = cacheUserBusiness.UserBusinesses.Where<UserBusiness>(o => o.Id == cacheUserBusiness.ActiveCompanyId).FirstOrDefault<UserBusiness>()
                        }
                    };
                }


            }
            catch (Exception ex)
            {
                response = new Response<UserInfo>()
                {
                    TransactionStatus = Utility.GetTransactionStatus(WebTransactionStatus.InternalServerError)

                };
                Utility.Logger.Info(string.Format("CRITICAL ISSUE|GetUserCompanyies|loginID:{0}", _loginId));
                Utility.Logger.Error(string.Format("Utility|GetUserCompanyies|Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static Response<UserInfo> GetUserDetailCache(string _loginId)
        {
            Response<UserInfo> response = null;
            try
            {
                CacheUserBusiness cacheUserBusiness = null;
                string strBusiness = string.Empty;
                Utility.CachingProvider.Get<string>(GetCacheKey(_loginId), out strBusiness);
                if (!string.IsNullOrEmpty(strBusiness))
                {
                    cacheUserBusiness = JsonConvert.DeserializeObject<CacheUserBusiness>(strBusiness);
                    if (cacheUserBusiness != null)
                    {
                        response = new Response<UserInfo>()
                        {
                            TransactionStatus = new Transaction() { IsSuccess = true },
                            Data = new UserInfo()
                            {
                                Business = cacheUserBusiness.UserBusinesses,
                                ActiveBusiness = cacheUserBusiness.UserBusinesses.Where<UserBusiness>(o => o.Id == cacheUserBusiness.ActiveCompanyId).FirstOrDefault<UserBusiness>()
                            }
                        };

                    }
                }

                if (response == null || (response != null && response.TransactionStatus == null) || (response != null && response.TransactionStatus != null && response.TransactionStatus.IsSuccess == false))
                {
                    response = new Response<UserInfo>()
                    {
                        TransactionStatus = new Transaction() { IsSuccess = false, Error = new Error() { Code = 404, Description = "User Company not found." } },
                        Data = null
                    };
                }



            }
            catch (Exception ex)
            {
                response = new Response<UserInfo>()
                {
                    TransactionStatus = Utility.GetTransactionStatus(WebTransactionStatus.InternalServerError)

                };
                Utility.Logger.Info(string.Format("CRITICAL ISSUE|GetUserDetailCache|loginID:{0}", _loginId));
                Utility.Logger.Error(string.Format("Utility|GetUserDetailCache|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static DateTime GetStartDate(DateTime _date)
        {
            DateTime response = DateTime.MinValue;
            try
            {
                response = new DateTime(_date.Year, _date.Month, _date.Day, 0, 0, 0);
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetStartDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static DateTime GetEndDate(DateTime _date)
        {
            DateTime response = DateTime.MinValue;
            try
            {
                response = new DateTime(_date.Year, _date.Month, _date.Day, 23, 59, 59);
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetStartDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static DataTable ConvertObjectToDatatable<T>(List<T> _obj)
        {
            DataTable response = null;
            try
            {
                PropertyDescriptorCollection properties = TypeDescriptor.GetProperties(typeof(T));
                response = new DataTable();
                for (int i = 0; i < properties.Count; i++)
                {
                    PropertyDescriptor property = properties[i];
                    response.Columns.Add(property.Name, property.PropertyType);
                }
                object[] values = new object[properties.Count];
                foreach (T item in _obj)
                {
                    for (int i = 0; i < values.Length; i++)
                    {
                        values[i] = properties[i].GetValue(item);
                    }
                    response.Rows.Add(values);
                }
                return response;
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|ConvertObjectToDatatable|Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static string GetCurrencySymbol(string _code)
        {
            string response = null;
            try
            {
                if (Utility.Portal.Currencies != null && Utility.Portal.Currencies.Currency != null && Utility.Portal.Currencies.Currency.Count > 0)
                {
                    Currency currency = Utility.Portal.Currencies.Currency.Where<Currency>(o => o.Code.Equals(_code, StringComparison.OrdinalIgnoreCase)).FirstOrDefault<Currency>();
                    if (currency != null)
                    {
                        response = currency.Symbol;
                    }
                }

            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetStartDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static bool IsImageFileExist(string _imgAbsolutePath)
        {
            bool isExist = false;
            try
            {
                HttpWebRequest httpWebReq = (HttpWebRequest)WebRequest.Create(_imgAbsolutePath);
                httpWebReq.Method = "HEAD";
                HttpWebResponse resp = (HttpWebResponse)httpWebReq.GetResponse();
                if (resp != null && resp.StatusCode == HttpStatusCode.OK && !string.IsNullOrEmpty(resp.ContentType) && resp.ContentType.ToLower().Contains("image"))
                {
                    isExist = true;
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Common.Utility.IsImageFileExist|Exception:{0}", ex.ToString()));
            }
            return isExist;
        }

        public static string GetBusinessLogo(int _companyId)
        {
            string path = string.Empty;
            try
            {
                string tempDrivePath = string.Format("{0}/logo-{1}.jpg", Utility.Settings.CompanyLogoPath, _companyId);
                if (File.Exists(tempDrivePath))
                {
                    path = string.Format("{0}logos/logo-{1}.jpg?v={2}", Utility.Settings.ApplicationUIURL, _companyId, Guid.NewGuid());
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Common.Utility.GetBusinessLogo|Exception:{0}", ex.ToString()));
            }
            return path;
        }

        public static DateTime GetFinancialYearStartDate(UserBusiness claim)
        {
            DateTime response = new DateTime(DateTime.Now.Year, 1, 1);
            try
            {
                string finYearStart = claim.FinancialYearStart;
                DateTime currentDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
                if (!string.IsNullOrEmpty(finYearStart))
                {
                    string[] dayMonth = finYearStart.Split('-');
                    if (dayMonth != null && dayMonth.Length == 2)
                    {
                        DateTime tempDate = new DateTime(DateTime.Now.Year, Convert.ToInt32(dayMonth[1]), Convert.ToInt32(dayMonth[0]));
                        if (tempDate > currentDate)
                        {
                            response = tempDate.AddYears(-1);
                        }
                        else
                        {
                            response = tempDate;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetFinancialYearStartDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static DateTime GetFinancialYearEndDate(UserBusiness claim)
        {
            DateTime response = new DateTime(DateTime.Now.Year, 12, 31);
            try
            {
                string finYearEnd = claim.FinancialYearEnd;
                DateTime currentDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
                if (!string.IsNullOrEmpty(finYearEnd))
                {
                    string[] dayMonth = finYearEnd.Split('-');
                    if (dayMonth != null && dayMonth.Length == 2)
                    {
                        DateTime tempDate = new DateTime(DateTime.Now.Year, Convert.ToInt32(dayMonth[1]), Convert.ToInt32(dayMonth[0]));
                        if (tempDate < currentDate)
                        {
                            response = tempDate.AddYears(1);
                        }
                        else
                        {
                            response = tempDate;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetFinancialYearEndDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static string GetUserIdGuid()
        {
            return Guid.NewGuid().ToString();
        }
        public static Modules GetModuleSubs()
        {
            Modules response = null;
            try
            {
                response = GetModuleAction();
                response.Module.ForEach(m => m.ModuleSubs
                                                      .ForEach(ms => ms.ModuleActions = null));


            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility.GetModuleSubs:Exception:{0}", ex.ToString()));
            }
            return response;
        }

        public static Modules GetModuleAction()
        {
            Modules response = null;
            ModuleSettings Module = null;
            string ModuleJsonPath = "";
            try
            {
                ModuleJsonPath = string.Format("{0}/{1}.json", Settings.ModuleJsonPath, Settings.ModuleJsonfile);
                if (!File.Exists(ModuleJsonPath))
                {
                    Module = ModuleProcedure.GetModuleSetting(Settings.DatabaseConnection.AkountoDB);
                    if (Module.ModuleSubs != null && Module.ModuleSubs.Count > 0)
                    {
                        response = new Modules();
                        response.Module = Module.Module.OrderBy(ob => ob.OrderId).Select(o => new ModuleList()
                        {
                            Id = o.Id,
                            Name = o.Name,
                            Description = o.Description,
                            ModuleSubs = Module.ModuleSubs.Where(c => c.ModuleId == o.Id).OrderBy(ob => ob.OrderId).Select(h => new ModuleSubs()
                            {
                                Id = h.Id,
                                Name = h.Name,
                                ModuleId = h.ModuleId,
                                ModuleActions = Module.ModuleActions.Where(a => a.ModuleSubId == h.Id).OrderBy(ob => ob.OrderId).Select(ma => new ModuleActions()
                                {
                                    Id = ma.Id,
                                    Name = ma.Name,
                                    ModuleSubId = ma.ModuleSubId
                                }
                                  ).ToList()
                            }).ToList()
                        }).ToList();

                        string Json = JsonConvert.SerializeObject(response);
                        using (StreamWriter OutpurFile = new StreamWriter(ModuleJsonPath))
                        {
                            OutpurFile.Write(Json);
                        }
                        Utility.Module = response;
                    }
                }
                else
                {
                    string Json = "";
                    using (StreamReader JsonFile = new StreamReader(ModuleJsonPath))
                    {
                        Json = JsonFile.ReadToEnd();
                    }
                    response = JsonConvert.DeserializeObject<Modules>(Json);
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility.GetModuleSubs:Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static DateTime GetFirstInvoiceDate(DateTime _agrementDate, int _weekDays, int _monthDate, int _yearMonth, InvoiceScheduleType _invoiceScheduleType)
        {
            DateTime response = _agrementDate;
            try
            {
                switch (_invoiceScheduleType)
                {
                    case InvoiceScheduleType.Weekly:
                        _agrementDate = _agrementDate.Date;
                        int agrementDay = (int)_agrementDate.DayOfWeek;
                        if (agrementDay != _weekDays)
                        {
                            int dayAdd = 0;
                            if (_weekDays < agrementDay)
                            {
                                dayAdd = (((int)(WeekDays.Saturday)) - agrementDay) + (_weekDays + 1);
                            }
                            else
                            {
                                dayAdd = _weekDays - agrementDay;
                            }
                            response = _agrementDate.AddDays(dayAdd);
                        }
                        break;
                    case InvoiceScheduleType.Monthly:
                        _agrementDate = _agrementDate.Date;
                        int iAgreementDate = _agrementDate.Day;
                        int noDays = DateTime.DaysInMonth(_agrementDate.Year, _agrementDate.Month);
                        if (_monthDate >= iAgreementDate && iAgreementDate <= noDays)
                        {
                            response = _agrementDate.AddDays(_monthDate - iAgreementDate);

                        }
                        else
                        {
                            response = new DateTime(_agrementDate.Year, _agrementDate.Month, _monthDate);
                        }
                        break;
                    case InvoiceScheduleType.Yearly:
                        _agrementDate = _agrementDate.Date;

                        if (_yearMonth < _agrementDate.Month)
                        {
                            response = new DateTime(_agrementDate.Year + 1, _yearMonth, _monthDate);
                        }
                        else
                        {
                            _agrementDate.AddMonths(_agrementDate.Month + (_yearMonth - _agrementDate.Month));
                            response = new DateTime(_agrementDate.Year, _agrementDate.Month, _monthDate);
                        }
                        break;
                    default:
                        response = _agrementDate;
                        break;
                }
            }
            catch (Exception ex)
            {
                Utility.Logger.Error(string.Format("Utility|GetFirstInvoiceDate|Exception:{0}", ex.ToString()));
            }
            return response;
        }
        public static Image GetImageFromBase64(string base64)
        {
            Image image = null;
            try
            {
                byte[] bytes = Convert.FromBase64String(base64);

                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    image = Image.FromStream(ms);
                }
            }
            catch (Exception ex)
            {
                image = null;
                Utility.Logger.Error("GetImageFromBase64| EXCEPTION:" + ex.ToString());
            }
            return image;
        }
        public static Image ResizeImage(Image image, int IMAGE_WIDTH, int IMAGE_HEIGHT)
        {
            Image response = null;
            try
            {
                if (image.Width > IMAGE_WIDTH || image.Height > IMAGE_HEIGHT)
                {
                    int originalWidth = image.Width;
                    int originalHeight = image.Height;
                    float percentWidth = (float)IMAGE_WIDTH / (float)originalWidth;
                    float percentHeight = (float)IMAGE_HEIGHT / (float)originalHeight;
                    float percent = percentHeight < percentWidth ? percentHeight : percentWidth;
                    int newWidth = (int)(originalWidth * percent);
                    int newHeight = (int)(originalHeight * percent);
                    response = new Bitmap(newWidth, newHeight);
                    using (System.Drawing.Graphics graphicsHandle = Graphics.FromImage(response))
                    {
                        graphicsHandle.DrawImage(image, 0, 0, newWidth, newHeight);
                    }
                }
                else
                {
                    response = image;
                }
            }
            catch (Exception ex)
            {
                response = image;
                Utility.Logger.Error("ResizeImage| EXCEPTION:" + ex.ToString());
            }

            return response;
        }
    }
}