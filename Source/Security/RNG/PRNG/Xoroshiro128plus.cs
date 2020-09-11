﻿using System;
using System.Security.Cryptography;

namespace Litdex.Security.RNG.PRNG
{
	/// <summary>
	/// Xoroshiro128plus PRNG is improved from Xoroshift128.
	/// http://xoroshiro.di.unimi.it/xoroshiro128plus.c
	/// </summary>
	public class Xoroshiro128plus : Random64
    {
        private ulong _State1, _State2;

		/// <summary>
		/// Constructor.
		/// </summary>
		public Xoroshiro128plus()
        {
            this.Reseed();
        }

        /// <summary>
        /// Constructor with defined seed.
        /// </summary>
        /// <param name="seed1"></param>
        /// <param name="seed2"></param>
        public Xoroshiro128plus(ulong seed1, ulong seed2)
        {
            this._State1 = seed1;
			this._State2 = seed2;
        }

		#region Protected Method

		/// <summary>
		/// Generate next random number.
		/// </summary>
		/// <returns></returns>
		protected override ulong Next()
		{
			ulong s0 = this._State1;
			ulong s1 = this._State2;
			ulong result = this._State1 + this._State2;

			s1 ^= s0;
			this._State1 = this.RotateLeft(s0, 24) ^ s1 ^ (s1 << 16); // a, b
			this._State2 = this.RotateLeft(s1, 37); // c

			return result;
		}

		protected ulong RotateLeft(ulong val, int shift)
		{
			return (val << shift) | (val >> (64 - shift));
		}

		#endregion Protected Method

		#region Public Method

		/// <summary>
		/// The name of the algorithm this generator implements.
		/// </summary>
		/// <returns></returns>
		public override string AlgorithmName()
		{
			return "Xoroshiro 128+";
		}

		/// <summary>
		/// Seed with RNGCryptoServiceProvider.
		/// </summary>
		public override void Reseed()
		{
			byte[] bytes = new byte[8];
			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetNonZeroBytes(bytes);
				this._State1 = BitConverter.ToUInt64(bytes, 0);
				rng.GetNonZeroBytes(bytes);
				this._State2 = BitConverter.ToUInt64(bytes, 0);
			}
		}

		/// <summary>
		/// 2^64 calls to NextLong(), it can be used to generate 2^64
		/// non-overlapping subsequences for parallel computations.
		/// </summary>
		public void NextJump()
        {
            ulong[] JUMP = { 0xDF900294D8F554A5, 0x170865DF4B3201FC };
            ulong seed1 = 0, seed2 = 0;

            for (int i = 0; i < 2; i++)
            {
                for (int b = 0; b < 64; b++)
                {
                    if ((JUMP[i] & (1UL << b)) != 0)
                    {
                        seed1 ^= JUMP[0];
                        seed2 ^= JUMP[1];
                    }
                    this.NextLong();
                }
            }

			this._State1 = seed1;
			this._State2 = seed2;
            Array.Clear(JUMP, 0, JUMP.Length);
        }

		#endregion Public
	}
}