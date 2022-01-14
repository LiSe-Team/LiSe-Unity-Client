using Newtonsoft.Json;
using System;

namespace LiSe
{
    public class Token
    {
        [JsonProperty(PropertyName ="product_id", Required = Required.Always)]
        public UInt64 productId;
        [JsonProperty(PropertyName = "access_level", Required = Required.AllowNull)]
        public UInt16? accessLevel;
        [JsonProperty(PropertyName = "licence_key", Required = Required.Always)]
        public UInt64 licenceKey;
        [JsonProperty(PropertyName = "usage_id", Required = Required.Always)]
        public UInt64 usageId;
        [JsonProperty(PropertyName = "instance_code", Required = Required.Always)]
        public string usageCode;
        [JsonProperty(PropertyName = "instance_type", Required = Required.Always)]
        public UInt64 instancetype;
        [JsonProperty(PropertyName = "time_stamp", Required = Required.Always)]
        public DateTime timeStamp;
    }
}
