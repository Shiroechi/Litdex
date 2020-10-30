namespace Litdex.Utilities.Number
{
    public static class Prime
    {
        /// <summary>
        /// Check the value is prime or not.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <returns>
        /// True, if the the value is prime.
        /// False, otherwise.
        /// </returns>
        public static bool IsPrime(short value)
        {
            for (var i = 2; i < value; i++)
            {
                if (value % i == 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Check the value is prime or not.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <returns>
        /// True, if the the value is prime.
        /// False, otherwise.
        /// </returns>
        public static bool IsPrime(int value)
        {
            for (var i = 2; i < value; i++)
            {
                if (value % i == 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Check the value is prime or not.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <returns>
        /// True, if the the value is prime.
        /// False, otherwise.
        /// </returns>
        public static bool IsPrime(uint value)
        {
            for (var i = 2u; i < value; i++) 
            {
                if (value % i == 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Check the value is prime or not.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <returns>
        /// True, if the the value is prime.
        /// False, otherwise.
        /// </returns>
        public static bool IsPrime(long value)
        {
            for (var i = 2; i < value; i++)
            {
                if (value % i == 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Check the value is prime or not.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <returns>
        /// True, if the the value is prime.
        /// False, otherwise.
        /// </returns>
        public static bool IsPrime(ulong value)
        {
            for (var i = 2UL; i < value; i++)
            {
                if (value % i == 0)
                {
                    return false;
                }
            }
            return true;
        }
    }
}