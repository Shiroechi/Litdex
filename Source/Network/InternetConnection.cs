using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace Litdex.Network
{
	/// <summary>
	/// 
	/// </summary>
    public class InternetConnection
    {
		/// <summary>
		/// Constructor.
		/// </summary>
        private InternetConnection()
        {

        }

		/// <summary>
		/// Desctructor.
		/// </summary>
		~InternetConnection()
		{

		}

        /// <summary>
        /// Check internet connection from http request.
        /// </summary>
        /// <returns>
        /// True, if there's internet connection.
        /// False, otherwise.
        /// </returns>
        public static bool InternetConnecion()
        {
			if(InternetConnection.CheckNetworkAdapter() == false)
			{
				return false;
			}

            try
            {
                using (var client = new WebClient())
                {
                    using (client.OpenRead("http://clients3.google.com/generate_204"))
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }

            //[DllImport("wininet.dll")]
            //private extern static bool InternetGetConnectedState(out int description, int reservedValue);

            //public static bool IsInternetAvailable()
            //{
            //    int description;
            //    return InternetGetConnectedState(out description, 0);
            //}
        }

		/// <summary>
		/// Check is there avaible network adapter to this device.
		/// </summary>
		/// <returns></returns>
		public static bool CheckNetworkAdapter()
		{
			return System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();
		}

        /// <summary>
        /// Get public IP of your connected network.
        /// </summary>
        /// <returns></returns>
        public static string PublicIP()
        {
            try
            {
                string externalIP;
                using (var client = new WebClient())
                {
                    externalIP = client.DownloadString("http://checkip.dyndns.org/");
                }
                
                externalIP = (new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")).Matches(externalIP)[0].ToString();
                return externalIP;
            }
            catch
            {
                return null;
            }
        }

		/// <summary>
		/// Get local IP that assigned to your device.
		/// </summary>
		/// <returns></returns>
		//public static string LocalIP()
		//{
		//	if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
		//	{
		//		return null;
		//	}

		//	var host = Dns.GetHostEntry(Dns.GetHostName());
		//	foreach (var ip in host.AddressList)
		//	{
		//		if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
		//		{
		//			return ip.ToString();
		//		}
		//	}
		//	return "no";
		//	//IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

		//	//return host.AddressList.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToString();
		//}

		/// <summary>
		/// Get local IP that assigned to your device.
		/// </summary>
		/// <returns></returns>
		public static string LocalIP()
		{
			if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
			{
				return null;
			}

			IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
			return host.AddressList.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToString();
		}

		/// <summary>
		/// Get Default Gateway from connected network.
		/// </summary>
		/// <returns></returns>
		public static string DefaultGateway()
        {
            IPAddress result = null;            
            var cards = NetworkInterface.GetAllNetworkInterfaces().ToList();
            if (cards.Any())
            {
                foreach (var card in cards)
                {
                    var props = card.GetIPProperties();
                    if (props == null)
                    {
                        continue;
                    }

                    var gateways = props.GatewayAddresses;
                    if (!gateways.Any())
                    {
                        continue;
                    }

                    var gateway = gateways.FirstOrDefault(g => g.Address.AddressFamily.ToString() == "InterNetwork");
                    if (gateway == null)
                    {
                        continue;
                    }

                    result = gateway.Address;
                    break;
                };
            }
			
            return result.ToString();
        }

		/// <summary>
		/// Get MAC Address from this computer.
		/// </summary>
		/// <returns></returns>
		private static string MACAddress()
		{
			return "";
		}
    }
}