using Newtonsoft.Json;
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using PemUtils;
using System.Net.Http;
using System.Threading.Tasks;

namespace LiSe
{

    public class Service
    {
        [JsonProperty(PropertyName = "Key", Required = Required.Always)]
        public string Key;
        [JsonProperty(PropertyName = "server_url", Required = Required.Always)]
        public string ServerUrl;
        [JsonProperty(PropertyName = "max_age", Required = Required.Always)]
        public int MaxAge;

        public async static Task<Service> Get(string file)
        {
            try
            {
                char[] result;
                StringBuilder builder = new StringBuilder();
                using (StreamReader reader = File.OpenText(file))
                {
                    result = new char[reader.BaseStream.Length];
                    await reader.ReadAsync(result, 0, (int)reader.BaseStream.Length);
                    reader.Close();
                }

                foreach (char c in result)
                {
                    builder.Append(c);
                }
                string payload = builder.ToString();
                Service server = JsonConvert.DeserializeObject<Service>(payload);
                return server;
            }
            catch (Exception e)
            {
                return default;
            }
        }
    }

    /// <summary>
    /// Class that represents a LiSe Usage
    /// </summary>
    public class Usage 
    {
        [JsonProperty(PropertyName = "signature", Required = Required.Always)]
        public string b64Signature;
        [JsonProperty(PropertyName = "token", Required = Required.Always)]
        public string Token;

        private bool m_verified = false;

        /// <summary>
        /// Verify that the Usage is crytographically valid and has not been tampered with.
        /// </summary>
        /// <returns>Boolean True if valid</returns>
        public bool Verify(Service server)
        {
            try
            {
                using (MemoryStream text = new MemoryStream(Encoding.UTF8.GetBytes(server.Key)))
                using (PemReader reader = new PemReader(text))
                {
                    RSAParameters pkeyParams = reader.ReadRsaKey();
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(pkeyParams);
                        byte[] signature = Convert.FromBase64String(b64Signature);
                        byte[] data = Encoding.UTF8.GetBytes(Token);
                        m_verified = rsa.VerifyData(data, CryptoConfig.MapNameToOID("SHA1"), signature);
                        return m_verified;
                    }
                }
            } catch (Exception e)
            {
                return false;
            }
        }

        /// <summary>
        /// Validate the Usage with the LiSe Server. If the server is not avalaible check the timecode to see
        /// if the Usage is still valid for offline use.
        /// </summary>
        /// <returns></returns>
        public async Task ValidateAsync(Service server)
        {
            using (HttpClient www = new HttpClient())
            {
                int age = DateTime.Now.Subtract(GetToken().timeStamp).Days;
                try
                {
                    using StringContent payload = new StringContent(JsonConvert.SerializeObject(this), Encoding.UTF8, "application/json");
                    using HttpResponseMessage response = await www.PostAsync(server.ServerUrl + "validate_key", payload);
                    switch (response.StatusCode)
                    {
                        case System.Net.HttpStatusCode.OK:
                            string content = await response.Content.ReadAsStringAsync();
                            Usage update = JsonConvert.DeserializeObject<Usage>(content);
                            Token = update.Token;
                            b64Signature = update.b64Signature;
                            break;
                        case System.Net.HttpStatusCode.RequestTimeout:
                            if (age > 5) throw new AuthenticationException();
                            break;
                        default:
                            throw new AuthenticationException();
                    }
                } catch
                {
                    if (age > server.MaxAge) throw new AuthenticationException();
                }
            }
        }

        /// <summary>
        /// Get the verified token from the Usage or return null
        /// </summary>
        /// <returns>Token or null</returns>
        public Token GetToken()
        {
            return m_verified ? JsonConvert.DeserializeObject<Token>(Token) : null ;
        }

        /// <summary>
        /// Get a new Localkey instance
        /// </summary>
        /// <param name="server"></param>
        /// <param name="auth_code"></param>
        /// <param name="auth_type"></param>
        /// <param name="instance_code"></param>
        /// <param name="instance_type"></param>
        /// <param name="product_id"></param>
        /// <returns></returns>
        public async static Task<Usage> GetAsync(Service server, 
            string auth_code,
            int auth_type,
            string instance_code,
            int instance_type,
            UInt64 product_id)
        {
            using (HttpClient www = new HttpClient())
            {
                try
                {
                    object p = new
                    {
                        auth_code = auth_code,
                        auth_type = auth_type,
                        instance_code = instance_code,
                        instance_type = instance_type,
                        product_id = product_id
                    };
                    using StringContent payload = new StringContent(JsonConvert.SerializeObject(p), Encoding.UTF8, "application/json");
                    using HttpResponseMessage response = await www.PostAsync(server.ServerUrl + "get_key", payload);
                    switch (response.StatusCode)
                    {
                        case System.Net.HttpStatusCode.OK:
                            string content = await response.Content.ReadAsStringAsync();
                            return JsonConvert.DeserializeObject<Usage>(content);
                        default:
                            throw new AuthenticationException();
                    }
                }
                catch
                {
                    throw new AuthenticationException();
                }
            }
        }

    }

    public class AuthenticationException : Exception
    {

    }
}
