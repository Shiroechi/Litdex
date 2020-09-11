namespace Litdex.Security.OTP
{
	/// <summary>
	/// List of hash mode that OTP support.
	/// </summary>
	public enum OTPHashMode
	{
		/// <summary>
		/// Using default hash function.
		/// </summary>
		ANY,

		/// <summary>
		/// Secure Hash Algorithm 1.
		/// </summary>
		SHA1,

		/// <summary>
		/// Secure Hash Algorithm 2 256bit.
		/// </summary>
		SHA256,

		/// <summary>
		/// Secure Hash Algorithm 2 512 bit.
		/// </summary>
		SHA512,

		/// <summary>
		/// Blake2b 512 bit.
		/// </summary>
		Blake2b
	}
}
