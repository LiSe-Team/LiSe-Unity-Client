
using System;
using System.IO;
using System.Text;
using System.Net.Http;

namespace LiSe
{
    public class LiseApi
    {
        private static readonly HttpClient httpClient;

        static LiseApi()
        {
            httpClient = new HttpClient();
        }

        public Usage Validate(Usage key)
        {

            return default;

        }
    }
}

