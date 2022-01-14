using UnityEngine;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace LiSe
{
    public class LocalKey
    {
        private string file;
        
        [JsonProperty(PropertyName = "key")]
        public Usage key;

        public async static Task<LocalKey> Get(string file)
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
                LocalKey config = JsonConvert.DeserializeObject<LocalKey>(payload);
                config.file = file;
                return config;
            } catch (Exception e)
            {
                Debug.LogError(e.ToString());
                return default;
            }
        }

        public async Task Put()
        {
            string payload = JsonConvert.SerializeObject(this, Formatting.Indented);
            using (StreamWriter writer = new StreamWriter(file, false))
            {
                await writer.WriteAsync(payload);
            }
        }

        public async Task Put(string f)
        {
            file = f;
            Directory.CreateDirectory(Path.GetDirectoryName(f));
            await Put();
        }
    }
}
