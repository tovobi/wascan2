using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using WhiteMagic;

namespace wascan2
{
	class Scan
	{

		[DllImport("kernel32.dll")]
		static extern uint GetLastError();

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate IntPtr WardenDelegate(IntPtr ptr, uint adress, uint len);

		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void LuaExecuteBufferDelegate(string lua, string fileName, uint pState);
		private static LuaExecuteBufferDelegate LuaExecute;

		/*
		wowProc = Process.GetProcessesByName("wow");
		baseAddress = (uint)wowProc[0].MainModule.BaseAddress;
		moduleSize = (uint)wowProc[0].MainModule.ModuleMemorySize;
		*/
		private static uint baseAddress = (uint)Process.GetCurrentProcess().MainModule.BaseAddress;
		private static uint moduleSize = (uint)Process.GetCurrentProcess().MainModule.ModuleMemorySize;

		public Scan()
		{
			//LuaExecute = Magic.Instance.RegisterDelegate<LuaExecuteBufferDelegate>(baseAddress + 0x50229);
			LuaExecute = Magic.Instance.RegisterDelegate<LuaExecuteBufferDelegate>(baseAddress + 0x27DD1);
			SearchWarden(new byte[] { 0x74, 0x02, 0xF3, 0xA5, 0xB1, 0x03, 0x23, 0xCA });
		}

		private static void makeDetour(uint ptr)
		{
			Magic.Instance.Detours.RemoveAll();
			Magic.Instance.Detours.CreateAndApply(Magic.Instance.RegisterDelegate<WardenDelegate>(ptr + 0xE), new WardenDelegate(WardenCave), "WardenHook");
		}

		#region pattern scan
		private unsafe void SearchWarden(byte[] Signature)
		{
			uint currentAddr = baseAddress;
			currentAddr = 0x01a00000;
			uint Max = 0;
			int index = 0;
			int iScan = 0;
			uint old;
			Win32.MEMORY_BASIC_INFORMATION mbi = new Win32.MEMORY_BASIC_INFORMATION();

			do
			{
				iScan++;
				Win32.VirtualQuery(ref currentAddr, ref mbi, sizeof(Win32.MEMORY_BASIC_INFORMATION));
				//Console.WriteLine(iScan.ToString() + " " + currentAddr.ToString("X"));
				//Console.WriteLine("Search Region: " + iScan + "\tAddress: " + currentAddr.ToString("X") + "/" + currentAddr.ToString() + " || \t AB: " + mbi.AllocationBase + "\t AP: " + mbi.AllocationProtect + "\t RS: " + mbi.RegionSize + "\t S: " + mbi.State + "\t T: " + mbi.Type);
				if ((mbi.RegionSize <= 0x9000) && (mbi.State == 4096) && (mbi.Type == 131072))
				{
					bool vp = Win32.VirtualProtect((IntPtr)currentAddr, (uint)mbi.RegionSize, 0x40, out old);
					Console.WriteLine(Marshal.GetLastWin32Error() + " " + vp.ToString() + " " + currentAddr.ToString("X"));

					
					if (vp)
					{
						Console.WriteLine("Search Region: " + iScan + "\tAddress: " + currentAddr.ToString("X") + "/" + currentAddr.ToString() + " || \t AB: " + mbi.AllocationBase + "\t AP: " + mbi.AllocationProtect + "\t RS: " + mbi.RegionSize + "\t S: " + mbi.State + "\t T: " + mbi.Type);

						if (currentAddr < Max)
							return;
						else
							Max = currentAddr;

						for (int x = (int)currentAddr; x < (currentAddr + mbi.RegionSize); x++)
						{
							if (*(byte*)x == Signature[index])
							{
								Console.WriteLine(x.ToString("X") + "|" + Signature[index].ToString("X") + "  ");
								index++;
							}
							else
							{
								index = 0;
							}
							
							if (index >= Signature.Length)
							{
								Console.ReadLine();
								index = 0;
							}
							/*
							if (index >= Signature.Length)
							{
								Console.WriteLine("makeDetour");
								Console.WriteLine("Search Region: " + iScan + "\tAddress: " + currentAddr.ToString("X") + "/" + currentAddr.ToString() + " || \t AB: " + mbi.AllocationBase + "\t AP: " + mbi.AllocationProtect + "\t RS: " + mbi.RegionSize + "\t S: " + mbi.State + "\t T: " + mbi.Type);
								makeDetour((uint)(x - Signature.Length + 1));
								Thread.Sleep(5000);
								return;
								
							}
							*/
						}
					}
				}
				currentAddr += (uint)mbi.RegionSize;
				if (currentAddr >= 0x01b00000)
				{
					Thread.Sleep(10000);
				}
				//currentAddr += 0x8;
			} while (true);
		}
		/* Possible Protectionflags for VirtualProtect
		PAGE_NOACCESS = 0x01,
		PAGE_READONLY = 0x02,
		PAGE_READWRITE = 0x04,
		PAGE_WRITECOPY = 0x08,
		PAGE_EXECUTE = 0x10,
		PAGE_EXECUTE_READ = 0x20,
		PAGE_EXECUTE_READWRITE = 0x40,
		PAGE_EXECUTE_WRITECOPY = 0x80,
		PAGE_GUARD = 0x100,
		PAGE_NOCACHE = 0x200,
		PAGE_WRITECOMBINE = 0x400
		*/

	#endregion

	private static IntPtr WardenCave(IntPtr ptr, uint adress, uint len)
		{
			Console.WriteLine("WardenCave");
			if (adress < baseAddress + moduleSize)
			{
				Console.WriteLine("LuaExec");
				LuaExecute("print('found: |cffff00000x" + (adress - baseAddress).ToString("X") + "|r, length: |cff00ff00" + len.ToString() + "b|r')", "mylua.lua", 0);
			}
			return (IntPtr)Magic.Instance.Detours["WardenHook"].CallOriginal(ptr, adress, len);
			
		}
	}
}