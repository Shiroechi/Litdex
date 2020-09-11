using System;
using System.Security.Cryptography;

namespace Litdex.Security.RNG.PRNG
{
	/// <summary>
	/// Based on Wyhash https://github.com/wangyi-fudan/wyhash
	/// </summary>
	public class WyRng : Random64
	{
        #region Member

        private ulong _Seed;

        #endregion Member

        #region Constructor & Destructor

        public WyRng(ulong seed = 0)
		{
            if(seed != 0)
			{
                this._Seed = seed;
			}
            else
			{
                this.Reseed();
			}
		}

        ~WyRng()
		{
            this._Seed = 0;
		}

        #endregion Constructor & Destructor

        #region Protected Method

        protected override ulong Next()
        {
            this._Seed += 0xa0761d6478bd642f;
            var result = this.MUM(this._Seed ^ 0xe7037ed1a0b428db, this._Seed);
            return result;
        }

        protected ulong MUM(ulong x, ulong y)
		{
			ulong hi, lo;

            lo = x * y;

            ulong x0 = (uint)x;
            ulong x1 = x >> 32;

            ulong y0 = (uint)y;
            ulong y1 = y >> 32;

            ulong p11 = x1 * y1;
            ulong p01 = x0 * y1;
            ulong p10 = x1 * y0;
            ulong p00 = x0 * y0;

            // 64-bit product + two 32-bit values
            ulong middle = p10 + (p00 >> 32) + (uint)p01;

            // 64-bit product + two 32-bit values
            hi = p11 + (middle >> 32) + (p01 >> 32);

            return hi ^ lo;
		}

		#endregion Protected Method

		#region Public Method

		public override string AlgorithmName()
		{
            return "WyRng";
		}

		public override void Reseed()
		{
			byte[] bytes = new byte[8];
			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetNonZeroBytes(bytes);
				this._Seed = BitConverter.ToUInt64(bytes, 0);
			}
		}

		#endregion Public Method

	}
}
