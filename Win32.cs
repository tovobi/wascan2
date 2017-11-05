using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace wascan2
{
	class Win32
	{
		// REQUIRED CONSTS

		const int PROCESS_QUERY_INFORMATION = 0x0400;
		const int MEM_COMMIT = 0x00001000;
		const int PAGE_READWRITE = 0x04;
		const int PROCESS_WM_READ = 0x0010;


		// REQUIRED METHODS

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern int VirtualQuery(ref uint lpAddress,	ref MEMORY_BASIC_INFORMATION lpBuffer,	int dwLength);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

		// REQUIRED STRUCTS

		public struct MEMORY_BASIC_INFORMATION
		{
			public int BaseAddress;
			public int AllocationBase;
			public int AllocationProtect;
			public int RegionSize;
			public int State;
			public int Protect;
			public int Type;
		}


		public struct SYSTEM_INFO
		{
			public ushort processorArchitecture;
			ushort reserved;
			public uint pageSize;
			public IntPtr minimumApplicationAddress;
			public IntPtr maximumApplicationAddress;
			public IntPtr activeProcessorMask;
			public uint numberOfProcessors;
			public uint processorType;
			public uint allocationGranularity;
			public ushort processorLevel;
			public ushort processorRevision;
		}


		// finally...

	}
}