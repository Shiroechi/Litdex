using System;
using System.Collections.Generic;

namespace Litdex.Security.RNG
{
	/// <summary>
	/// Base class for 32 bit RNG.
	/// </summary>
	public abstract class Random32 : IRNG
	{
		#region Constructor & Destructor

		public Random32()
		{

		}

		~Random32()
		{

		}

		#endregion Constructor & Destructor

		#region Protected Method

		/// <summary>
		/// Generate next random number.
		/// </summary>
		/// <returns>32 bit random integer.</returns>
		protected abstract uint Next();

		#endregion Protected Method

		#region Public Method

		public virtual string AlgorithmName()
		{
			return "Random32";
		}

		public virtual void Reseed()
		{
			//do nothing.
		}

		public virtual bool NextBoolean()
		{
			return this.NextInt() % 2 == 0;
		}

		public virtual byte NextByte()
		{
			return this.NextBytes(1)[0];
		}

		public virtual byte NextByte(byte lower, byte upper)
		{
			if (lower >= upper)
			{
				throw new Exception("The lower bound must not be greater than or equal to the upper bound.");
			}

			byte diff = (byte)(upper - lower + 1);
			return (byte)(lower + (this.NextByte() % diff));
		}

		public virtual uint NextInt()
		{
			return this.Next();
		}

		public virtual uint NextInt(uint lower, uint upper)
		{
			if (lower >= upper)
			{
				throw new Exception("The lower bound must not be greater than or equal to the upper bound.");
			}

			uint diff = upper - lower + 1;
			return lower + (this.Next() % diff);
		}

		public virtual ulong NextLong()
		{
			byte[] bytes1 = BitConverter.GetBytes(this.Next());
			byte[] bytes2 = BitConverter.GetBytes(this.Next());
			byte[] bytes = new byte[8];

			bytes[0] = bytes1[0];
			bytes[1] = bytes1[1];
			bytes[2] = bytes1[2];
			bytes[3] = bytes1[3];
			bytes[4] = bytes2[0];
			bytes[5] = bytes2[1];
			bytes[6] = bytes2[2];
			bytes[7] = bytes2[3];

			//for (int i = 0; i < 8; i++)
			//{
			//	if(i < 4)
			//	{
			//		bytes[i] = bytes1[i];
			//	}
			//	else
			//	{
			//		bytes[i] = bytes2[i - 4];
			//	}
			//}

			//remove most left significant bit
			//bytes[0] = (byte)(bytes[0] >> 1);

			return BitConverter.ToUInt64(bytes, 0);
		}

		public virtual ulong NextLong(ulong lower, ulong upper)
		{
			if (lower >= upper)
			{
				throw new Exception("The lower bound must not be greater than or equal to the upper bound.");
			}

			ulong diff = upper - lower + 1;
			return lower + (this.NextLong() % diff);
		}

		public virtual double NextDouble()
		{
			return NextLong() * (1.0 / (1L << 53)); //java conversion method
			//return (double)(NextLong() >> 11) * (1.0 / long.MaxValue);
		}

		public virtual double NextDouble(double lower, double upper)
		{
			if (lower >= upper)
			{
				throw new Exception("The lower bound must not be greater than or equal to the upper bound.");
			}

			double diff = upper - lower + 1;
			return lower + (this.NextDouble() % diff);
		}
		
		public virtual byte[] GetBytes(int length)
		{
			if (length <= 0)
			{
				throw new Exception("Bytes length can't lower than or equal to 0.");
			}

			byte[] bytes = new byte[length];

			int counter = 0;
			int leftover = 0;
			int current = bytes.Length;

			while (counter != bytes.Length)
			{
				//calculate leftover
				if (current >= 4)
				{
					current -= 4;
					leftover = 4;
				}
				else
				{
					leftover = current;
				}

				uint data = this.NextInt();

				//copy 4 byte from Integer to bytes array
				for (int i = 0; i < leftover; i++)
				{
					bytes[counter] = (byte)data;
					data >>= 8;
					counter++;
				}
			}
			return bytes;
		}

		/// <summary>
		/// Generate random byte[] value from generator.
		/// </summary>
		/// <param name="length">Output length.</param>
		/// <returns></returns>
		public virtual byte[] NextBytes(int length)
		{
			uint sample = this.Next();
			byte[] data = new byte[length];

			for (int i = 1; i <= length; i++)
			{
				if (i % 4 == 0)
				{
					sample = this.Next();
				}
				data[i - 1] = (byte)(sample);
				sample >>= 8;
			}
			return data;
		}

		/// <summary>
		/// Select one element randomly.
		/// </summary>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <returns></returns>
		public virtual T Choice<T>(T[] items)
		{
			return items[(int)this.NextInt(0, (uint)(items.Length - 1))];
		}

		/// <summary>
		/// Select abritary element randomly.
		/// </summary>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <param name="count">The desired amount to select.</param>
		/// <returns></returns>
		public virtual T[] Choice<T>(T[] items, int count)
		{
			List<T> temp = new List<T>(items);
			return this.Choice<T>(temp, count).ToArray();
		}

		/// <summary>
		/// Select one element randomly.
		/// </summary>
		/// <remarks>
		/// More slower because need boxing/unboxing.
		/// </remarks>
		/// <param name="items">Set of items to choose.</param>
		/// <returns></returns>
		public virtual object Choice(object[] items)
		{
			return items[(int)this.NextInt(0, (uint)(items.Length - 1))];
		}

		/// <summary>
		/// Select abritary element randomly.
		/// </summary>
		/// <remarks>
		/// More slower because need boxing/unboxing.
		/// </remarks>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <param name="count">The desired amount to select.</param>
		/// <returns></returns>
		/// <returns></returns>
		public virtual object[] Choice(object[] items, int count)
		{
			List<object> temp = new List<object>(items);
			return this.Choice(temp, count).ToArray();
		}

		/// <summary>
		/// Select one element randomly.
		/// </summary>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <returns></returns>
		public virtual T Choice<T> (List<T> items)
		{
			return items[(int)this.NextInt(0, (uint)(items.Count - 1))];
		}

		/// <summary>
		/// Select abritary element randomly.
		/// </summary>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <param name="count">The desired amount to select.</param>
		/// <returns></returns>
		public virtual List<T> Choice<T>(List<T> items, int count)
		{
			if (count > items.Count)
			{
				throw new Exception("Count can't greater than items length(" + items.Count + ")");
			}
			else if (count < 1)
			{
				throw new Exception("Count can't lower than 1.");
			}

			List<T> selected = new List<T>();

			int index = (int)this.NextInt(0, (uint)(items.Count - 1));

			while (selected.Count < count)
			{
				if (selected.Contains(items[index]))
				{
					index = (int)this.NextInt(0, (uint)(items.Count - 1));
					continue;
				}

				selected.Add(items[index]);
			}
			
			return selected;
		}

		/// <summary>
		/// Select one element randomly.
		/// </summary>
		/// <remarks>
		/// More slower because need boxing/unboxing.
		/// </remarks>
		/// <param name="items">Set of items to choose.</param>
		/// <returns></returns>
		public virtual object Choice(List<object> items)
		{
			return items[(int)this.NextInt(0, (uint)(items.Count - 1))];
		}

		/// <summary>
		/// Select abritary element randomly.
		/// </summary>
		/// <remarks>
		/// More slower because need boxing/unboxing.
		/// </remarks>
		/// <typeparam name="T">Data type</typeparam>
		/// <param name="items">Set of items to choose.</param>
		/// <param name="count">The desired amount to select.</param>
		/// <returns></returns>
		/// <returns></returns>
		public virtual List<object> Choice(List<object> items, int count)
		{
			if (count > items.Count)
			{
				throw new Exception("Count can't greater than items length(" + items.Count + ")");
			}
			else if (count < 1)
			{
				throw new Exception("Count can't lower than 1.");
			}

			List<object> selected = new List<object>();

			int index = (int)this.NextInt(0, (uint)items.Count - 1);

			while (selected.Count < count)
			{
				if (selected.Contains(items[index]))
				{
					index = (int)this.NextInt(0, (uint)(items.Count - 1));
					continue;
				}

				selected.Add(items[index]);
			}

			return selected;
		}

		#endregion Public Method
	}
}
