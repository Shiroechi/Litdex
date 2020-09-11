namespace Litdex.Security.RNG
{
    /// <summary>
    /// Interface structure for Random Number Generator (RNG).
    /// </summary>
    public interface IRNG
    {
		/// <summary>
		/// The name of the algorithm this generator implements.
		/// </summary>
		/// <returns>The name of this RNG.</returns>
		string AlgorithmName();

		/// <summary>
		/// Seed with RNGCryptoServiceProvider.
		/// </summary>
		void Reseed();

		/// <summary>
		/// Generate Boolean value from generator.
		/// </summary>
		/// <returns></returns>
		bool NextBoolean();

        /// <summary>
        /// Generate Integer value from generator.
        /// </summary>
        /// <returns></returns>
        uint NextInt();

		/// <summary>
		/// Generate Integer value between 
		/// lower bound and upper bound from generator.
		/// </summary>
		/// <param name="lower">Lower bound.</param>
		/// <param name="upper">Upper bound.</param>
		/// <returns>s</returns>
		uint NextInt(uint lower, uint upper);

		/// <summary>
		/// Generate Long value from generator. 
		/// </summary>
		/// <returns></returns>
		ulong NextLong();

		/// <summary>
		/// Generate Long value between 
		/// lower bound and upper bound from generator.
		/// </summary>
		/// <param name="lower">Lower bound.</param>
		/// <param name="upper">Upper bound.</param>
		/// <returns></returns>
		ulong NextLong(ulong lower, ulong upper);

		/// <summary>
		/// Generate Double value from generator.
		/// </summary>
		/// <returns></returns>
		double NextDouble();

		/// <summary>
		/// Generate Double value between 
		/// lower bound and upper bound from generator.
		/// </summary>
		/// <param name="lower">Lower bound.</param>
		/// <param name="upper">Upper bound.</param>
		/// <returns></returns>
		double NextDouble(double lower, double upper);
		
		/// <summary>
		/// Generate random byte[] value from generator.
		/// </summary>
		/// <param name="length">Output length.</param>
		/// <returns></returns>
		byte[] GetBytes(int length);
    }
}