# -----------------------------------------------------------------------------
# Script: AssemblyHelper.ps1 
# Author: Ewout van der Linden
# Date: 23-09-2013
# Updated: 31-01-2018
# -----------------------------------------------------------------------------

$signature = @"
	public const uint IASSEMBLYCACHE_INSTALL_FLAG_REFRESH = 0x00000001;
	public const uint IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH = 0x00000002;

	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED = 1;
	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE = 2;
	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED = 3;
	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING = 4;
	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES = 5;
	public const uint IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND = 6;

	public const uint S_OK = 0x00000000;
	public const uint S_FALSE = 0x00000001;

	public const uint SUCCESS = 0x00130000;
	public const uint ERROR = 0x80130000;

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate int CreateAssemblyCacheDelegate(out IAssemblyCache ppAsmCache, uint dwReserved);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate int CreateAssemblyEnumDelegate(out IAssemblyEnum ppEnum, IntPtr pUnkReserved, IAssemblyName pName, ASM_CACHE_FLAGS dwFlags, IntPtr pvReserved);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate int CreateInstallReferenceEnumDelegate(out IInstallReferenceEnum ppEnum, IAssemblyName pName, int dwFlags, IntPtr pvReserved);

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate int CreateAssemblyNameObjectDelegate(out IAssemblyName ppAssemblyNameObj, [MarshalAs(UnmanagedType.LPWStr)] string szAssemblyName, CREATE_ASM_NAME_OBJ_FLAGS dwFlags, IntPtr pvReserved);


	[DllImport("kernel32.dll")]
	public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
	public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)] string filename);

	[DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	//[DllImport("Fusion.dll", CharSet = CharSet.Auto)]
	//public static extern int CreateAssemblyCache(out IAssemblyCache ppAsmCache, uint dwReserved);

	[DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern int LoadString(IntPtr hInstance, uint uID, out IntPtr lpBuffer, int nBufferMax);

	[Flags]
	public enum LoadLibraryFlags : uint {
		DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
		LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
		LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
		LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
		LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
		LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
	}

	[Flags]
	public enum ASM_CACHE_FLAGS : uint {
		ASM_CACHE_ZAP = 0x01,
		ASM_CACHE_GAC = 0x02,
		ASM_CACHE_DOWNLOAD = 0x04,
		ASM_CACHE_ROOT = 0x08,
		ASM_CACHE_ROOT_EX = 0x80
	}

	[Flags]
	public enum ASM_DISPLAY_FLAGS : uint {
		ASM_DISPLAYF_VERSION = 0x01,
		ASM_DISPLAYF_CULTURE = 0x02,
		ASM_DISPLAYF_PUBLIC_KEY_TOKEN = 0x04,
		ASM_DISPLAYF_PUBLIC_KEY = 0x08,
		ASM_DISPLAYF_CUSTOM = 0x10,
		ASM_DISPLAYF_PROCESSORARCHITECTURE = 0x20,
		ASM_DISPLAYF_LANGUAGEID = 0x40,
		ASM_DISPLAYF_RETARGET = 0x80,
		ASM_DISPLAYF_CONFIG_MASK = 0x100,
		ASM_DISPLAYF_MVID = 0x200,
		ASM_DISPLAYF_FULL =
			ASM_DISPLAYF_VERSION |
			ASM_DISPLAYF_CULTURE |
			ASM_DISPLAYF_PUBLIC_KEY_TOKEN |
			ASM_DISPLAYF_RETARGET |
			ASM_DISPLAYF_PROCESSORARCHITECTURE
	}

	public enum CREATE_ASM_NAME_OBJ_FLAGS : uint {
		CANOF_PARSE_DISPLAY_NAME = 0x1,
		CANOF_SET_DEFAULT_VALUES = 0x2
	}

	public sealed class InstallReference {

		public InstallReference(Guid scheme, String id, String data) {
			GuidScheme = scheme;
			Identifier = id;
			Description = data;
		}

		public Guid GuidScheme {
			get;
			private set;
		}

		public String Identifier {
			get;
			private set;
		}

		public String Description {
			get;
			private set;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct FUSION_INSTALL_REFERENCE {
		public uint cbSize;
		public uint flags;
		public Guid guidScheme;
		[MarshalAs(UnmanagedType.LPWStr)]
		public string identifier;
		[MarshalAs(UnmanagedType.LPWStr)]
		public string description;
	}

	[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("582dac66-e678-449f-aba6-6faaec8a9394")]
	public interface IInstallReferenceItem {
		[PreserveSig()]
		int GetReference(
						out IntPtr pRefData,
						int flags,
						IntPtr pvReserced);
	}

	[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("56b1a988-7c0c-4aa2-8639-c3eb5a90226f")]
	public interface IInstallReferenceEnum {
		[PreserveSig()]
		int GetNextInstallReferenceItem(
						out IInstallReferenceItem ppRefItem,
						int flags,
						IntPtr pvReserced);
	}

	[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("21b8916c-f28e-11d2-a473-00c04f8ef448")]
	public interface IAssemblyEnum {
		[PreserveSig()]
		int GetNextAssembly(IntPtr pvReserved, out IAssemblyName ppName, int flags);
		[PreserveSig()]
		int Reset();
		[PreserveSig()]
		int Clone(out IAssemblyEnum ppEnum);
	}

	[ComImport, Guid("e707dcde-d1cd-11d2-bab9-00c04f8eceae"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAssemblyCache {
		[PreserveSig]
		int UninstallAssembly(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName, IntPtr pvReserved, out uint pulDisposition);
		[PreserveSig]
		int QueryAssemblyInfo(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName, IntPtr pAsmInfo);
		[PreserveSig]
		int CreateAssemblyCacheItem(uint dwFlags, IntPtr pvReserved, out IAssemblyCacheItem ppAsmItem, [MarshalAs(UnmanagedType.LPWStr)] string pszAssemblyName);
		[PreserveSig]
		int CreateAssemblyScavenger(out object ppAsmScavenger);
		[PreserveSig]
		int InstallAssembly(uint dwFlags, [MarshalAs(UnmanagedType.LPWStr)] string pszManifestFilePath, IntPtr pvReserved);
	}

	[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("9e3aaeb4-d1cd-11d2-bab9-00c04f8eceae")]
	public interface IAssemblyCacheItem {
		void CreateStream([MarshalAs(UnmanagedType.LPWStr)] string pszName, uint dwFormat, uint dwFlags, uint dwMaxSize, out System.Runtime.InteropServices.ComTypes.IStream ppStream);
		void IsNameEqual(IAssemblyName pName);
		void Commit(uint dwFlags);
		void MarkAssemblyVisible(uint dwFlags);
	}

	[ComImport, Guid("CD193BC0-B4BC-11d2-9833-00C04FC31D2E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
	public interface IAssemblyName {
		[PreserveSig]
		int SetProperty(uint PropertyId, IntPtr pvProperty, uint cbProperty);
		[PreserveSig]
		int GetProperty(uint PropertyId, IntPtr pvProperty, ref uint pcbProperty);
		[PreserveSig]
		int Finalize();
		[PreserveSig]
		int GetDisplayName(System.Text.StringBuilder szDisplayName, ref uint pccDisplayName, ASM_DISPLAY_FLAGS dwDisplayFlags);
		//int GetDisplayName(IntPtr szDisplayName, ref uint pccDisplayName, uint dwDisplayFlags);
		[PreserveSig]
		int BindToObject(object refIID, object pAsmBindSink, IApplicationContext pApplicationContext, [MarshalAs(UnmanagedType.LPWStr)] string szCodeBase, long llFlags, int pvReserved, uint cbReserved, out int ppv);
		[PreserveSig]
		int GetName(out uint lpcwBuffer, out int pwzName);
		[PreserveSig]
		int GetVersion(out uint pdwVersionHi, out uint pdwVersionLow);
		[PreserveSig]
		int IsEqual(IAssemblyName pName, uint dwCmpFlags);
		[PreserveSig]
		int Clone(out IAssemblyName pName);
	}

	[ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("7c23ff90-33af-11d3-95da-00a024a85b51")]
	public interface IApplicationContext {
		void SetContextNameObject(IAssemblyName pName);
		void GetContextNameObject(out IAssemblyName ppName);
		void Set([MarshalAs(UnmanagedType.LPWStr)] string szName, int pvValue, uint cbValue, uint dwFlags);
		void Get([MarshalAs(UnmanagedType.LPWStr)] string szName, out int pvValue, ref uint pcbValue, uint dwFlags);
		void GetDynamicDirectory(out int wzDynamicDir, ref uint pdwSize);
	}

	public static string GetFrameworkPath() {
		string msCorLibDirectory = System.IO.Path.GetDirectoryName(new Uri(System.Reflection.Assembly.GetAssembly(typeof(object)).CodeBase).LocalPath);
		if (Environment.Version.Major < 4) {
			int i = msCorLibDirectory.LastIndexOf('\\');
			if (i >= 0) {
				return msCorLibDirectory.Substring(0, i + 1) + "v4.0.30319";
			}
			return msCorLibDirectory;
		}
		else {
			return msCorLibDirectory;
		}
	}

	public static string GetFullPath(string path, string filename) {
		if (System.IO.Path.IsPathRooted(filename)) {
			return new System.IO.FileInfo(filename).FullName;
		}
		else {
			return new System.IO.FileInfo(path.TrimEnd('\\') + '\\' + filename.TrimStart('\\')).FullName;
		}
	}

	public static int GetAssemblyInstallReferences(string name, out System.Collections.Generic.List<InstallReference> references) {
		references = null;

		string msCorLibDirectory = GetFrameworkPath();
		string filename = System.IO.Path.Combine(msCorLibDirectory, "fusion.dll");

		IntPtr fusionModule = LoadLibrary(filename);
		if (fusionModule == IntPtr.Zero) {
			throw new DllNotFoundException(filename);
		}

		IntPtr createAssemblyNameObjectMethodPtr = GetProcAddress(fusionModule, "CreateAssemblyNameObject");
		if (createAssemblyNameObjectMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateAssemblyNameObject method not found");
		}

		IntPtr createInstallReferenceEnumMethodPtr = GetProcAddress(fusionModule, "CreateInstallReferenceEnum");
		if (createInstallReferenceEnumMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateInstallReferenceEnum method not found");
		}

		CreateAssemblyNameObjectDelegate createAssemblyNameObjectMethod = (CreateAssemblyNameObjectDelegate)Marshal.GetDelegateForFunctionPointer(createAssemblyNameObjectMethodPtr, typeof(CreateAssemblyNameObjectDelegate));
		CreateInstallReferenceEnumDelegate createInstallReferenceEnumMethod = (CreateInstallReferenceEnumDelegate)Marshal.GetDelegateForFunctionPointer(createInstallReferenceEnumMethodPtr, typeof(CreateInstallReferenceEnumDelegate));

		IAssemblyName assemblyName;
		int hresult = createAssemblyNameObjectMethod(out assemblyName, name, CREATE_ASM_NAME_OBJ_FLAGS.CANOF_PARSE_DISPLAY_NAME, IntPtr.Zero);
		if (hresult != 0) {
			return hresult;
		}

		IInstallReferenceEnum installReferenceEnum;
		hresult = createInstallReferenceEnumMethod(out installReferenceEnum, assemblyName, 0, IntPtr.Zero);
		if (hresult != 0) {
			return hresult;
		}

		System.Collections.Generic.List<InstallReference> result = new System.Collections.Generic.List<InstallReference>();

		InstallReference installReference;
		do {
			hresult = GetNextReference(installReferenceEnum, out installReference);
			if (hresult != 0) {
				return hresult;
			}

			if (installReference != null) {
				result.Add(installReference);
			}
		}
		while (installReference != null);

		references = result;
		return 0;
	}

	public static int GetAssemblies(string name, string publicKey, bool exactNameMatch, bool outputFullName, out System.Collections.Generic.List<string> assmblies) {

		assmblies = null;

		string msCorLibDirectory = GetFrameworkPath();
		string filename = System.IO.Path.Combine(msCorLibDirectory, "fusion.dll");

		IntPtr fusionModule = LoadLibrary(filename);
		if (fusionModule == IntPtr.Zero) {
			throw new DllNotFoundException(filename);
		}

		IntPtr createAssemblyCacheMethodPtr = GetProcAddress(fusionModule, "CreateAssemblyCache");
		if (createAssemblyCacheMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateAssemblyCache method not found");
		}

		IntPtr CreateAssemblyEnumMethodPtr = GetProcAddress(fusionModule, "CreateAssemblyEnum");
		if (CreateAssemblyEnumMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateAssemblyEnum method not found");
		}

		IntPtr CreateInstallReferenceEnumMethodPtr = GetProcAddress(fusionModule, "CreateInstallReferenceEnum");
		if (CreateInstallReferenceEnumMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateInstallReferenceEnum method not found");
		}

		CreateAssemblyEnumDelegate createAssemblyCacheMethod = (CreateAssemblyEnumDelegate)Marshal.GetDelegateForFunctionPointer(CreateAssemblyEnumMethodPtr, typeof(CreateAssemblyEnumDelegate));
		CreateInstallReferenceEnumDelegate CreateInstallReferenceEnumMethod = (CreateInstallReferenceEnumDelegate)Marshal.GetDelegateForFunctionPointer(CreateInstallReferenceEnumMethodPtr, typeof(CreateInstallReferenceEnumDelegate));

		IAssemblyName fusionName = null;
		IAssemblyEnum assemblyEnum;
		int hresult = createAssemblyCacheMethod(out assemblyEnum, IntPtr.Zero, fusionName, ASM_CACHE_FLAGS.ASM_CACHE_GAC, IntPtr.Zero);
		if (hresult != 0) {
			return hresult;
		}

		System.Collections.Generic.HashSet<string> result = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);

		do {
			hresult = assemblyEnum.GetNextAssembly((IntPtr)0, out fusionName, 0);
			if (hresult != 0) {
				if (hresult == S_FALSE) {
					assmblies = System.Linq.Enumerable.ToList(result);
					assmblies.Sort(StringComparer.OrdinalIgnoreCase);
					return 0;
				}
				return hresult;
			}

			if (fusionName != null) {

				System.Text.StringBuilder sDisplayName = new System.Text.StringBuilder(1024);
				uint iLen = 1024;

				hresult = fusionName.GetDisplayName(sDisplayName, ref iLen, ASM_DISPLAY_FLAGS.ASM_DISPLAYF_FULL);
				if (hresult != 0) {
					return hresult;
				}

				string assemblyName = sDisplayName.ToString();
				int x = assemblyName.IndexOf(',');
				if (x < 0) {
					continue;
				}
				string assemblyNameOnly = assemblyName.Substring(0, x);
				string assemblyPublicKey = null;
				x = assemblyName.IndexOf("PublicKeyToken=", x, StringComparison.Ordinal);
				if (x < 0) {
					continue;
				}
				int xx = assemblyName.IndexOf(',', x);
				if (xx >= 0) {
					assemblyPublicKey = assemblyName.Substring(x + 15, xx - x - 15);
				}
				else {
					assemblyPublicKey = assemblyName.Substring(x + 15);
				}

				bool isNameMatch = string.IsNullOrEmpty(name) || (exactNameMatch ? string.Equals(assemblyNameOnly, name, StringComparison.OrdinalIgnoreCase) : assemblyNameOnly.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
				bool isKeyMatch = string.IsNullOrEmpty(publicKey) || string.Equals(assemblyPublicKey, publicKey, StringComparison.OrdinalIgnoreCase);

				if (isNameMatch && isKeyMatch) {

					if (outputFullName && !result.Contains(assemblyName)) {
						result.Add(assemblyName);
					}
					else if (!outputFullName && !result.Contains(assemblyNameOnly)) {
						result.Add(assemblyNameOnly);
					}

					//IInstallReferenceEnum installReferenceEnum;
					//hresult = CreateInstallReferenceEnumMethod(out installReferenceEnum, fusionName, 0, IntPtr.Zero);
					//if (hresult != 0) {
					//	return hresult;
					//}

					//InstallReference installReference;
					//do {
					//	hresult = GetNextReference(installReferenceEnum, out installReference);
					//	if (hresult != 0) {
					//		return hresult;
					//	}

					//	if (installReference != null) {

					//	}
					//}
					//while (installReference != null);
				}
			}
		}
		while (fusionName != null);

		assmblies = System.Linq.Enumerable.ToList(result);
		assmblies.Sort(StringComparer.OrdinalIgnoreCase);
		return 0;
	}

	private static int GetNextReference(IInstallReferenceEnum installReferenceEnum, out InstallReference installReference) {
		installReference = null;
		IInstallReferenceItem item = null;
		int hresult = installReferenceEnum.GetNextInstallReferenceItem(out item, 0, IntPtr.Zero);
		if ((uint)hresult == 0x80070103) {   // ERROR_NO_MORE_ITEMS
			return 0;
		}

		if (hresult != 0) {
			return hresult;
		}

		IntPtr refData;
		hresult = item.GetReference(out refData, 0, IntPtr.Zero);
		if (hresult != 0) {
			return hresult;
		}

		FUSION_INSTALL_REFERENCE instRef = Marshal.PtrToStructure<FUSION_INSTALL_REFERENCE>(refData);
		installReference = new InstallReference(instRef.guidScheme, instRef.identifier, instRef.description);
		return 0;
	}

	public static int InstallAssembly(string path) {
		string msCorLibDirectory = GetFrameworkPath();
		string filename = System.IO.Path.Combine(msCorLibDirectory, "fusion.dll");

		IntPtr fusionModule = LoadLibrary(filename);
		if (fusionModule == IntPtr.Zero) {
			throw new DllNotFoundException(filename);
		}

		IntPtr createAssemblyCacheMethodPtr = GetProcAddress(fusionModule, "CreateAssemblyCache");
		if (createAssemblyCacheMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateAssemblyCache method not found");
		}

		CreateAssemblyCacheDelegate createAssemblyCacheMethod = (CreateAssemblyCacheDelegate)Marshal.GetDelegateForFunctionPointer(createAssemblyCacheMethodPtr, typeof(CreateAssemblyCacheDelegate));

		IAssemblyCache cache;
		//hresult = CreateAssemblyCache(out cache, 0);
		int hresult = createAssemblyCacheMethod(out cache, 0);
		if (hresult == 0) {
			hresult = cache.InstallAssembly(IASSEMBLYCACHE_INSTALL_FLAG_FORCE_REFRESH, path, IntPtr.Zero);
		}
		return hresult;
	}

	public static bool UninstallAssembly(string name, out int hresult, out uint disposition) {
		string msCorLibDirectory = GetFrameworkPath();
		string filename = System.IO.Path.Combine(msCorLibDirectory, "fusion.dll");

		IntPtr fusionModule = LoadLibrary(filename);
		if (fusionModule == IntPtr.Zero) {
			throw new DllNotFoundException(filename);
		}

		IntPtr createAssemblyCacheMethodPtr = GetProcAddress(fusionModule, "CreateAssemblyCache");
		if (createAssemblyCacheMethodPtr == IntPtr.Zero) {
			throw new Exception("CreateAssemblyCache method not found");
		}

		CreateAssemblyCacheDelegate createAssemblyCacheMethod = (CreateAssemblyCacheDelegate)Marshal.GetDelegateForFunctionPointer(createAssemblyCacheMethodPtr, typeof(CreateAssemblyCacheDelegate));

		IAssemblyCache cache;
		//hresult = CreateAssemblyCache(out cache, 0);
		hresult = createAssemblyCacheMethod(out cache, 0);
		if (hresult == 0) {
			hresult = cache.UninstallAssembly(0, name, IntPtr.Zero, out disposition);
			return true;
		}
		disposition = 0;
		return false;
	}
"@

Add-Type -MemberDefinition $signature -Name NativeMethods -Namespace AssemblyUtil
$nm = [AssemblyUtil.NativeMethods]

function GetMessage($hresult) {
	if (($hresult -band 4294901760) -ne $nm::SUCCESS -and ($hresult -band 4294901760) -ne $nm::ERROR) {
		return [String]::Empty;
	}
	
	$code = $hresult -band 65535;
	$mscorrc = $nm::GetFrameworkPath() + "\mscorrc.dll"
	$hMod = $nm::LoadLibraryEx($mscorrc, [IntPtr]::Zero, [AssemblyUtil.NativeMethods+LoadLibraryFlags]"LOAD_LIBRARY_AS_DATAFILE");
	$messageId = $code + 24576;
	
	$resourcePtr = [IntPtr]::Zero
	$res = $nm::LoadString($hMod, $messageId, [ref] $resourcePtr, 0);
	if ($res -eq 0 -or $resourcePtr -eq [IntPtr]::Zero) {
		return [System.String]::Empty;
	}
	
	$message = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($resourcePtr, $res);
	return $message;
}

function GetHeaderPath() {

    $sdkMainKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\NETFXSDK")
	if ($sdkMainKey -eq $null) {
		$sdkMainKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Microsoft SDKs\NETFXSDK")
		if ($sdkMainKey -eq $null) {
			return $null;
		}
	}
	$subKeys = $sdkMainKey.GetSubKeyNames();
	for ($i = $subKeys.Length - 1; $i -ge 0; $i -= 1) {
		$sdkKey = $sdkMainKey.OpenSubKey($subKeys[$i]);
		$path = [System.String]$sdkKey.GetValue("KitsInstallationFolder")
		if (![String]::IsNullOrEmpty($path)) {
			$targetFile = $path + "Include\CorError.h"
			if ([System.IO.File]::Exists($targetFile)) {
				return $targetFile;
			}
		}
	}
	
	return $null;
}

function FindConstant($hresult) {
	if (($hresult -band 4294901760) -eq $nm::SUCCESS) {
		$tofind = [String]::Format("SMAKEHR(0x{0:x})", ($hresult -band 65535));
	}
	elseif (($hresult -band 4294901760) -eq $nm::ERROR) {
		$tofind = [String]::Format("EMAKEHR(0x{0:x})", ($hresult -band 65535));
	}
	else {
		return [String]::Empty;
	}
	
	$header = GetHeaderPath;
	if (![String]::IsNullOrEmpty($header)) {
		$file = $null
		try {
			$file = [System.IO.File]::Open($header, [System.IO.FileMode]"Open", [System.IO.FileAccess]"Read", [System.IO.FileShare]"ReadWrite");
			$sr = new-object System.IO.StreamReader $file
			$headerContents = $sr.ReadToEnd();
		}
		finally {
			$file.Dispose();
		}
		
		$x = $headerContents.IndexOf($tofind);
		if ($x -ge 0) {
			$start = $headerContents.LastIndexOf("`n", $x);
			$end = $headerContents.IndexOf("`r", $x);

			if ($start -ge 0 -and $end -ge 0) {
				$line = $headerContents.Substring($start + 1, $end - $start - 1);
				if ($line.StartsWith("#define", [StringComparison]"Ordinal")) {
					$c = $line.IndexOf(' ', "#define ".Length);
					if ($c -ge 0) {
						$constant = $line.Substring("#define ".Length, $c - "#define ".Length);
						return $constant;
					}
				}
			}
		}
	}
	
	return [String]::Empty;
}

function DisplayHRESULT($hresult) {
	if (($hresult -band 4294901760) -eq $nm::SUCCESS) {
		$code = $hresult -band 65535;
		Write-Host "HRESULT: Success: 0x$($code.ToString(`"x4`")) ($($code))" -foreground green
	}
	elseif (($hresult -band 4294901760) -eq $nm::ERROR) {
		$code = $hresult -band 65535;
		$c = FindConstant $hresult;
		$message = GetMessage $hresult;
		Write-Host "HRESULT: Error: 0x$($code.ToString(`"x4`")) ($($code))" -foreground yellow
		Write-Host "Constant: $c" -foreground yellow
		Write-Host "Message: $message" -foreground yellow
	}
	else {
		Write-Host "HRESULT: Unknown: 0x$($hresult.ToString(`"x`"))" -foreground yellow
	}
}

function Get-AssemblyInstallReferences() {
	<#
		.SYNOPSIS
			The Get-AssemblyInstallReferences command will return the install references of an assembly installed in the GAC.
		
		.DESCRIPTION
			This command will return the install references of an assembly installed in the GAC.
		
		.EXAMPLE
			PS C:\> Get-AssemblyInstallReferences "AssemblyName, Version=1.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
			
			Description
			-----------
			Get all the install references for the specified assembly.
		
		.OUTPUTS
			List of assembly install references
		
		.NOTES
			Author: Ewout van der Linden
			Created: 08-10-2017
	#>
	[CmdletBinding()]
	param(
    [Parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [string]$name)
	
	process {
		$references = New-Object 'System.Collections.Generic.List[AssemblyUtil.NativeMethods+InstallReference]';
		$num = $nm::GetAssemblyInstallReferences($name, [ref]$references);
		if ($num -eq 0) {
			return $references
		}
		
		Write-Host "Enumeration failed" -foreground red
		DisplayHRESULT($num);
		return $null;
	}
}

function Get-Assemblies() {
	<#
		.SYNOPSIS
			The Get-Assembly command will enumerate the assemblies in the GAC.
		
		.DESCRIPTION
			This command will enumerate the assemblies in the GAC.
		
		.EXAMPLE
			PS C:\> Get-Assemblies -publicKey db937bc2d44ff139
			
			Description
			-----------
			List all the assemblies with the specified public key from the GAC.
		
		.OUTPUTS
			List of assemblies installed in the GAC
		
		.NOTES
			Author: Ewout van der Linden
			Created: 08-10-2017
	#>
	[CmdletBinding()]
	param(
    [Parameter(
        Position=1,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [string]$name,
	[Parameter(
        Position=2,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [string]$publicKey,
	[Parameter(
        Position=3,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [boolean]$exactNameMatch = $false,
	[Parameter(
        Position=4,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [boolean]$outputFullName = $false)
	
	process {
		$assemblies = New-Object 'System.Collections.Generic.List[System.String]';
		$num = $nm::GetAssemblies($name, $publicKey, $exactNameMatch, $outputFullName, [ref]$assemblies);
		if ($num -eq 0) {
			return $assemblies
		}
		
		Write-Host "Enumeration failed" -foreground red
		DisplayHRESULT($num);
		return $null;
	}
}

function Install-Assembly() {
	<#
		.SYNOPSIS
			The Install-Assembly command will install an assembly to the GAC.
		
		.DESCRIPTION
			This command will install an assembly to the GAC.
		
		.EXAMPLE
			PS C:\> Install-Assembly TestAssembly.dll
			
			Description
			-----------
			Installs the assembly file 'TestAssembly.dll' to the GAC.
		
		.OUTPUTS
			Success or failure
		
		.NOTES
			Author: Ewout van der Linden
			Created: 23-09-2013
	#>
	[CmdletBinding()]
	param(
    [Parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false)
    ]
    [string]$path)
	
	process {
		$workPath = Get-Location
		$path = $nm::GetFullPath($workPath, $path);
		$num = $nm::InstallAssembly($path);
		if ($num -eq 0) {
			return $true
		}
		
		$l = $path;
		$i = $l.LastIndexOf('\');
		if ($i -ge 0) {
			$l = $l.Substring($i + 1);
		}
		
		Write-Host "Install of '$l' failed" -foreground red
		DisplayHRESULT($num);
		return $false;
	}
}

function Uninstall-Assembly() {
	<#
		.SYNOPSIS
			The Uninstall-Assembly command will remove an assembly from the GAC.
		
		.DESCRIPTION
			This command will remove an assembly from the GAC.
		
		.EXAMPLE
			PS C:\> Uninstall-Assembly TestAssembly
			
			Description
			-----------
			Removes the assembly with the name 'TestAssembly' from the GAC.
		
		.OUTPUTS
			Success or failure
		
		.NOTES
			Author: Ewout van der Linden
			Created: 23-09-2013
	#>
	[CmdletBinding()]
	param(
    [Parameter(
        Position=1,
        Mandatory=$true,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$false)
    ]
    [string]$name)
	
	process {
		$num = 0;
		$disposition = 0;
		$success = $nm::UninstallAssembly($name, [ref]$num, [ref]$disposition);
		if (!$success) {
			Write-Host "Uninstall of '$name' failed" -foreground red
			DisplayHRESULT($num);
		}
		else {
			if (($num -eq 0 -and $disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED) -or ($num -eq 1 -and $disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED)) {
				return $true;
			}
			
			Write-Host "Uninstall of '$name' failed" -foreground red
			
			if ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED" -foreground yellow
			}
			elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE" -foreground yellow
			}
			elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED" -foreground yellow
			}
			elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING" -foreground yellow
			}
			elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES" -foreground yellow
			}
			elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND) {
				Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND" -foreground yellow
			}
			else {
				Write-Host "Status: Unknown" -foreground yellow
			}
		}
		return $false;
	}
}

function Uninstall-Assemblies() {
	<#
		.SYNOPSIS
			The Uninstall-Assemblies command will remove assemblies from the GAC.
		
		.DESCRIPTION
			This command will remove assemblies from the GAC.
		
		.EXAMPLE
			PS C:\> Uninstall-Assemblies -publicKey db937bc2d44ff139
			
			Description
			-----------
			Removes all the assemblies with the specified public key from the GAC.
		
		.OUTPUTS
			Number of assemblies removed
		
		.NOTES
			Author: Ewout van der Linden
			Created: 08-10-2017
	#>
	[CmdletBinding()]
	param(
    [Parameter(
        Position=1,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [string]$name,
	[Parameter(
        Position=2,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [string]$publicKey,
	[Parameter(
        Position=3,
        Mandatory=$false,
        ValueFromPipeline=$false,
        ValueFromPipelineByPropertyName=$true)
    ]
    [boolean]$exactNameMatch = $false)
	
	process {
		$result = 0;
		$assemblies = New-Object 'System.Collections.Generic.List[System.String]';
		$num = $nm::GetAssemblies($name, $publicKey, $exactNameMatch, $true, [ref]$assemblies);
		if ($num -ne 0) {
			Write-Host "Enumeration failed" -foreground red
			DisplayHRESULT($num);
			return -1;
		}
		
		$toRemove = @()
		foreach ($assembly in $assemblies) {
			$references = New-Object 'System.Collections.Generic.List[AssemblyUtil.NativeMethods+InstallReference]';
			$num = $nm::GetAssemblyInstallReferences($assembly, [ref]$references);
			if ($num -ne 0) {
				Write-Host "Enumeration failed" -foreground red
				DisplayHRESULT($num);
				return -1;
			}
			
			if ($references.Count -eq 0) {
				$toRemove += $assembly;
			}
			else {
				Write-Host "Skipping $($assembly) with install references" -foreground yellow
			}
		}
		
		$failed = $false;
		foreach ($assembly in $assemblies) {
			$num = 0;
			$disposition = 0;
			$success = $nm::UninstallAssembly($assembly, [ref]$num, [ref]$disposition);
			if (!$success) {
				Write-Host "Uninstall of '$assembly' failed" -foreground red
				DisplayHRESULT($num);
				$failed = $true;
			}
			else {
				if ($num -eq 0 -and $disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED) {
					Write-Host "Uninstalled $($assembly)"
					$result++;
					continue;
				}
				elseif ($num -eq 1 -and $disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED) {
					continue;
				}
				
				Write-Host "Uninstall of '$name' failed" -foreground red
				$failed = $true;
				
				if ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_UNINSTALLED" -foreground yellow
				}
				elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_STILL_IN_USE" -foreground yellow
				}
				elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_ALREADY_UNINSTALLED" -foreground yellow
				}
				elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_DELETE_PENDING" -foreground yellow
				}
				elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_HAS_INSTALL_REFERENCES" -foreground yellow
				}
				elseif ($disposition -eq $nm::IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND) {
					Write-Host "Status: IASSEMBLYCACHE_UNINSTALL_DISPOSITION_REFERENCE_NOT_FOUND" -foreground yellow
				}
				else {
					Write-Host "Status: Unknown" -foreground yellow
				}
			}
		}
		if ($failed) {
			return -1;
		}
		return $result;
	}
}
