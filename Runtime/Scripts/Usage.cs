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
    public class Usage 
    {
        string pKey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAIs6PNrhbuclxs2AenOJLozI4UmZUihvwszHPj/1/Ohs89e5WDHMuukY\nR0555/otUrSuoci+A1MtMrVRsE8ld2BMKY28Wc2m8B7A3XE9T07fWaCkc2HAsPnT\nhGSIN2g33GtQX7ThsccfGTnWQggCymol8pr3Wrp2UKUd7sjjIK1NAgMBAAE=\n-----END RSA PUBLIC KEY-----\n";
        string serverUrl = "https://virgis-6804b.ew.r.appspot.com/_ah/api/";
        //string serverUrl = "http://localhost:8000/_ah/api/";

        [JsonProperty(PropertyName = "signature", Required = Required.Always)]
        public string b64signature;
        [JsonProperty(PropertyName = "token", Required = Required.Always)]
        public string token;

        private bool verified = false;

        public bool verify()
        {
            try
            {
                using (MemoryStream text = new MemoryStream(Encoding.UTF8.GetBytes(pKey)))
                using (PemReader reader = new PemReader(text))
                {
                    RSAParameters pkeyParams = reader.ReadRsaKey();
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(pkeyParams);
                        byte[] signature = Convert.FromBase64String(b64signature);
                        byte[] data = Encoding.UTF8.GetBytes(token);
                        verified = rsa.VerifyData(data, CryptoConfig.MapNameToOID("SHA1"), signature);
                        return verified;
                    }
                }
            } catch
            {
                return false;
            }
        }

        public async Task validateAsync()
        {
            using (HttpClient www = new HttpClient())
            {
                int age = DateTime.Now.Subtract(GetToken().timeStamp).Days;
                try
                {
                    using StringContent payload = new StringContent(JsonConvert.SerializeObject(this), Encoding.UTF8, "application/json");
                    using HttpResponseMessage response = await www.PostAsync(serverUrl + "validate_key", payload);
                    switch (response.StatusCode)
                    {
                        case System.Net.HttpStatusCode.OK:
                            string content = await response.Content.ReadAsStringAsync();
                            Usage update = JsonConvert.DeserializeObject<Usage>(content);
                            token = update.token;
                            b64signature = update.b64signature;
                            break;
                        case System.Net.HttpStatusCode.RequestTimeout:
                            if (age > 5) throw new AuthenticationException();
                            break;
                        default:
                            throw new AuthenticationException();
                    }
                } catch
                {
                    if (age > 5) throw new AuthenticationException();
                }
            }
        }


        public Token GetToken()
        {
            return verified ? JsonConvert.DeserializeObject<Token>(token) : null ;
        }

    }

    public class AuthenticationException : Exception
    {

    }
}
