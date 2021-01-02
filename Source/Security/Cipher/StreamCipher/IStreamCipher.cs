namespace Litdex.Security.Cipher.StreamCipher
{
	internal interface IStreamCipher
	{
		/// <summary>
		/// The name of the algorithm this cipher implements.
		/// </summary>
		/// <returns></returns>
		string AlgorithmName();

		/// <summary>
		/// Reset the cipher.
		/// </summary>
		void Reset();

		/// <summary>
		/// Set up Key.
		/// </summary>
		/// <param name="key">Key.</param>
		void SetKey(byte[] key);

		/// <summary>
		/// Set up IV (Initialization Vector).
		/// </summary>
		/// <param name="iv">IV.</param>
		void SetIV(byte[] iv);

		/// <summary>
		/// Encrypt data.
		/// </summary>
		/// <param name="data">Data to encrypt.</param>
		/// <returns></returns>
		byte[] Encrypt(string data);

		/// <summary>
		/// Encrypt data.
		/// </summary>
		/// <param name="data">Data to encrypt.</param>
		/// <returns></returns>
		byte[] Encrypt(byte[] data);

		/// <summary>
		/// Decrypt data.
		/// </summary>
		/// <param name="data">Data to decrypt.</param>
		/// <returns></returns>
		byte[] Decrypt(string data);

		/// <summary>
		/// Decrypt data.
		/// </summary>
		/// <param name="data">Data to decrypt.</param>
		/// <returns></returns>
		byte[] Decrypt(byte[] data);
	}
}