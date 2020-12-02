using Litdex.Utilities.Extension;

namespace Litdex.Utilities.Base
{
	public static class Base64
	{
		/// <summary>
		/// Convert to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">byte[] to encode.</param>
		/// <returns>Encoded byte[].</returns>
		public static byte[] Encode(byte[] data)
		{
			return System.Convert.ToBase64String(data).GetBytes();
		}

		/// <summary>
		/// Convert to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">String to encode.</param>
		/// <returns>Encoded byte[].</returns>
		public static byte[] Encode(string data)
		{
			return Encode(data.GetBytes());
		}

		/// <summary>
		/// Convert to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">byte[] to encode.</param>
		/// <returns>Encoded string.</returns>
		public static string EncodeToString(byte[] data)
		{
			return System.Convert.ToBase64String(data);
		}

		/// <summary>
		/// Convert to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">String to encode.</param>
		/// <returns>Encoded string.</returns>
		public static string EncodeToString(string data)
		{
			return EncodeToString(data.GetBytes());
		}
				
		/// <summary>
		/// Convert Base64 string to byte[].
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">Base64 string.</param>
		/// <returns>Decoded byte[].</returns>
		public static byte[] Decode(string data)
		{
			return System.Convert.FromBase64String(data);
		}

		/// <summary>
		/// Convert Base64 string to byte[].
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">Base64 string.</param>
		/// <returns>Decoded byte[].</returns>
		public static byte[] Decode(byte[] data)
		{
			return Decode(data.GetString());
		}

		/// <summary>
		/// Convert Base64 string to original string.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">Base64 string.</param>
		/// <returns>Decoded string.</returns>
		public static string DecodeToString(string data)
		{
			return System.Convert.FromBase64String(data).GetString();
		}

		/// <summary>
		/// Convert Base64 string to original string.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="data">Base64 string.</param>
		/// <returns>Decoded string.</returns>
		public static string DecodeToString(byte[] data)
		{
			return DecodeToString(data.GetString());
		}
	}
}