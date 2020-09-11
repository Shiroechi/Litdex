using System;
using System.Collections.Generic;

//tidak lolos test case yang ada di RFC 6238

namespace Litdex.Security.OTP
{
	/// <summary>
	/// Timed-One-Time-Passwords (TOTP) 
	/// is a one-time password (OTP) algorithm based on HOTP. 
	/// <para>
	/// The specifications for this are found in RFC 6238
	/// http://tools.ietf.org/html/rfc6238
	/// </para>
	/// </summary>
	public class TOTP : OTP
	{
		#region Member

		/// <summary>
		/// Default time frame based on RFC 6238.
		/// <para>
		/// Time frame is usage period before the issued password expired.
		/// </para> 
		/// </summary>
		protected readonly int _TimeFrame = 30; //in second

		///// <summary>
		/// Based on midnight january 1st 1970
		/// </summary>
		//protected long _UnixTimeTicks = 621355968000000000L;

		protected readonly long _TicksToSeconds = 10000000;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		/// Create Timed-One-Time-Passwords (TOTP)
		/// with custom digit number and custom time frame.
		/// </summary>
		/// <param name="length">Output length.</param>
		public TOTP(int length = 6) : this(length, 30, OTPHashMode.SHA1)
		{
			
		}

		/// <summary>
		/// Create Timed-One-Time-Passwords (TOTP)
		/// with custom digit number and custom time frame.
		/// </summary>
		/// <param name="length">Output length.</param>
		/// <param name="time">Time frame.</param>
		/// <param name="mode">Hash mode.</param>
		public TOTP(int length, int time = 30, OTPHashMode mode = OTPHashMode.SHA1) : base(length, mode)
		{
			if (time <= 0) //0 second
			{
				throw new Exception("Time valid can't lower or equal than 0 second.");
			}
			else if(time > 600) //600 second => 10 minutes
			{
				throw new Exception("Time valid can't higher than 600 seconds.");
			}

			this._TimeFrame = time;
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~TOTP()
		{

		}

		#endregion Constructor & Destructor

		#region Protected Method

		///// <summary>
		///// Calculate counter value.
		///// </summary>
		///// <param name="now">Current datetime.</param>
		///// <returns></returns>
		//protected long CalculateCounter(DateTime now)
		//{
		//	return this.CalculateCounter(now, this._TimeFrame);
		//}

		///// <summary>
		///// Calculate counter value.
		///// </summary>
		///// <param name="now">Current datetime.</param>
		///// <param name="step">Time step.</param>
		///// <returns></returns>
		//protected long CalculateCounter(DateTime now, long step)
		//{
		//	//convert ticks to seconds
		//	long second = (now.Ticks - this._UnixTimeTicks) / 10000000L;

		//	//create time span 
		//	long time = second / step;
		//	return time;
		//}

		/// <summary>
		/// Convert <see cref="DateTime"/> Ticks to seconds.
		/// </summary>
		/// <param name="datetime">Current UTC <see cref="DateTime"/></param>
		/// <returns></returns>
		public long FromTickToSeconds(DateTime datetime)
		{
			return this.FromTickToSeconds(datetime.Ticks);
		}

		/// <summary>
		/// Convert ticks to seconds.
		/// </summary>
		/// <param name="ticks">Ticks from <see cref="DateTime"/></param>
		/// <returns></returns>
		public long FromTickToSeconds(long ticks)
		{
			return ticks / this._TicksToSeconds;
		}

		/// <summary>
		/// Convert second to ticks.
		/// </summary>
		/// <param name="seconds">Seconds to convert.</param>
		/// <returns></returns>
		public long FromSecondsToTicks(long seconds)
		{
			return seconds * this._TicksToSeconds;
		}


		/// <summary>
		/// Gets an enumberable of all the possible validation candidates
		/// </summary>
		/// <param name="initialFrame">The initial frame to validate</param>
		/// <returns>Enumberable of all possible frames that need to be validated</returns>
		protected IEnumerable<long> ValidationCandidates(long initialFrame, long previous = 0, long future = 0)
		{
			yield return initialFrame;
			for (int i = 1; i <= previous; i++)
			{
				//var val = initialFrame - this.FromSecondsToTicks(i);
				//if (val < 0)
				//{
				//	break;
				//}
				yield return initialFrame - this.FromSecondsToTicks(i);
			}

			for (int i = 1; i <= future; i++)
			{
				yield return initialFrame + this.FromSecondsToTicks(i);
			}				
		}

		#endregion Protected Method

		#region Public

		/// <summary>
		/// Generate password.
		/// </summary>
		/// <returns></returns>
		public string Generate()
		{
			return this.Generate(this._Key, DateTime.UtcNow.Ticks);
		}

		/// <summary>
		/// Generate password.
		/// </summary>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="counter">State counter.</param>
		/// <returns></returns>
		public string Generate(byte[] key, long counter)
		{
			//convert ticks to seconds
			long seconds = this.FromTickToSeconds(counter);
			return this.GeneratePassword(key, (ulong)seconds);
		}

		/// <summary>
		/// Verify <paramref name="input"/> code.
		/// </summary>
		/// <param name="input">OTP code.</param>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="datetime">Current datetime in UTC format.</param>
		/// <returns></returns>
		public bool Verify(string input, byte[] key, DateTime datetime)
		{
			return this.Verify(input, key, datetime.Ticks);
		}

		/// <summary>
		/// Verify <paramref name="input"/> code.
		/// </summary>
		/// <param name="input">OTP Code.</param>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="ticks">Current datetime ticks.</param>
		/// <returns></returns>
		public bool Verify(string input, byte[] key, long ticks)
		{
			foreach (var frame in this.ValidationCandidates(ticks, this._TimeFrame, this._TimeFrame))
			{
				var comparisonValue = this.Generate(key, frame);
				if (input == comparisonValue)
				{
					return true;
				}
			}
			return false;
		}

		/// <summary>
		/// Brute force to verify <paramref name="input"/>.
		/// </summary>
		/// <param name="input">OTP code.</param>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="ticks">Current datetime ticks.</param>
		/// <returns></returns>
		public bool Verify2(string input, byte[] key, long ticks)
		{
			//previous time
			for (int i = 0; i <= this._TimeFrame; i++) 
			{
				if (input == this.Generate(key, ticks - this.FromSecondsToTicks(i))) 
				{
					return true;
				}
			}

			//future time
			for (int i = 0; i <= this._TimeFrame; i++)
			{
				if (input == this.Generate(key, ticks + this.FromSecondsToTicks(1)))
				{
					return true;
				}
			}
			return false;
		}

		#endregion Public

	}
}
