namespace Litdex
{
	public static class Version
    {
        public static readonly string _Version = "1.2.1";
        public static readonly string _ReleaseDate = "2020-10-30";
#if NETSTANDARD2_0
        public static readonly string _Framework = "netstandard";
#elif NETCOREAPP2_1
        public static readonly string _Framework = "netstandard";
#endif
    }
}