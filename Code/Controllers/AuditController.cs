using System;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using claranet_audit.Models;
using System.IO;
using System.Security.Cryptography;
using System.Web;
using Newtonsoft.Json;
using System.Text;
using System.IO.Compression;
using System.Xml;
using System.Security;
using System.Runtime.InteropServices;

namespace claranet_audit.Controllers
{
    // Mv controller
    public class AuditController : Controller
    {
        //////// Global Objects ////////

        // Storage paths
        public static readonly string StorageRoot = Path.Combine(Directory.GetCurrentDirectory(),"Audit");
        public static readonly string CredentialsRoot = Path.Combine(StorageRoot,"Credentials");
        public static readonly string HostsRoot = Path.Combine(StorageRoot,"Hosts");
        public static readonly string ResultsRoot = Path.Combine(StorageRoot,"Results");
        public static readonly string PowerShellRoot = Path.Combine(StorageRoot,"PowerShell");
        public static readonly string DataRoot = Path.Combine(StorageRoot, "Data");

        // Cache objects
        public static List<Host> HostsCache = new List<Host>();
        public static List<Credential> CredentialsCache = new List<Credential>();
        
        // Scan info
        public static Scan CurrentScan = new Scan();
        public static string GlobalScanName = "";
        public static Process ScanProcess = new Process();
        public static ProcessStartInfo ScanProcessInfo = new ProcessStartInfo();

        // Encryption info
        private static bool IsFirstRun = true;
        private static byte[] RijndaelKey = new byte[32];
        private static byte[] RijndaelIV = new byte[16];


        //////// UI Actions ////////

        // Index page
        public IActionResult Index()
        {
            return View(IsFirstRun);
        }

        // Credentials page
        public IActionResult Credentials()
        {
            return View(CredentialsCache);
        }

        // Hosts page
        public IActionResult Hosts()
        {
            return View(HostsCache);
        }

        // Scan page
        public IActionResult Scan()
        {
            return View(CurrentScan);
        }

        // Export page
        public IActionResult Export()
        {
            return View();
        }

        // Shutdown page
        public IActionResult Shutdown()
        {
            return View();
        }

        // Error handler
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        //////// Service Actions ////////

        // Handles the first time configuration run
        public IActionResult FirstRun(string ScanName)
        {
            if (IsFirstRun)
            {
                // First let's make sure the root directories are created (git excludes empties)
                if (!Directory.Exists(CredentialsRoot))
                {
                    Directory.CreateDirectory(CredentialsRoot);
                }

                if (!Directory.Exists(HostsRoot))
                {
                    Directory.CreateDirectory(HostsRoot);
                }

                if (!Directory.Exists(ResultsRoot))
                {
                    Directory.CreateDirectory(ResultsRoot);
                }

                if (!Directory.Exists(DataRoot))
                {
                    Directory.CreateDirectory(DataRoot);
                }

                // Set our global scan name and clear the first run flag
                CurrentScan.Name = ScanName;
                GlobalScanName = ScanName;
                IsFirstRun = false;

                // Build our Rijndael key and init vector
                System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(RijndaelKey);
                System.Security.Cryptography.RandomNumberGenerator.Create().GetBytes(RijndaelIV);

                // Get our key and iv into seperated base 64 strings => byte[]
                string KeyDownload = String.Format("{0}:{1}",Convert.ToBase64String(RijndaelKey),Convert.ToBase64String(RijndaelIV));
                byte[] KeyBytes = Encoding.ASCII.GetBytes(KeyDownload);

                // Get our attachment content-disposition sorted
                var cd = new System.Net.Mime.ContentDisposition
                {
                    FileName = String.Format("{0}.auditkey",ScanName),
                    Inline = true,
                };

                // Add the cd response header and return the stream
                Response.Headers.Add("Content-Disposition", cd.ToString());
                return File(KeyBytes, "application/text");
            }
            else
            {
                return View("Index");
            }
        }
        
        // Clears out the host cache
        public IActionResult ClearHosts()
        {
            HostsCache.Clear();
            return RedirectToAction("Hosts");
        }

        // Clears out the credential cache
        public IActionResult ClearCredentials()
        {
            CredentialsCache.Clear();
            return RedirectToAction("Credentials");
        }

        // Processes the host file upload
        public async Task<IActionResult> UploadHosts(IFormFile HostsCsvFile)
        {
            // Get the hosts file name
            string HostsFileName = Path.GetFileName(HostsCsvFile.FileName);
            
            // Set the file path
            string HostsFilePath = Path.Combine(HostsRoot, HostsFileName);

            // Write from memory to disk
            using (var stream = new FileStream(HostsFilePath, FileMode.Create))
            {
                await HostsCsvFile.CopyToAsync(stream);
            }

            // Get our csv lines into a list
            List<string> CsvLines = System.IO.File.ReadAllLines(HostsFilePath).Skip(1).ToList();

            // Enumerate the lines in the CSV and add them to the Hosts cache
            foreach (string line in CsvLines)
            {
                // Split the line
                string[] Properties = line.Split(',');

                // Ok we need to make a decision here whether it's a host or cidr block
                if (Properties[0].Contains("/"))
                {
                    // Ok expand the cidr and add each host to the block
                    foreach (string Endpoint in Tools.CidrToIpRange(Properties[0]))
                    {
                        Properties[0] = Endpoint;
                        Tools.AddHostToCache(Properties);
                    }
                }
                else
                {
                    Tools.AddHostToCache(Properties);
                }
            }

            // Clear up the file
            System.IO.File.Delete(HostsFilePath);

            // And redirect back to our hosts page
            return RedirectToAction("Hosts");
        }

        // Processes a credential upload
        public async Task<IActionResult> UploadCredential(Credential c)
        {
            // Set the missing properties on the way by
            c.ID = Guid.NewGuid().ToString();

            // If this should be the default credential, set it thusly
            if (c.IsDefault || (CredentialsCache.Count(x => x.IsDefault && x.Type == c.Type) == 0))
            {
                // Secondary check here to overwrite default credential if already present
                CredentialsCache.Where(x => x.IsDefault && x.Type == c.Type).ToList().ForEach(oc => oc.IsDefault = false);

                // Set the default
                c.IsDefault = true;                
            }
            else 
            {
                c.IsDefault = false;
            }

            // Now deal with the private key file if exists
            if (c.PrivateKeyFile != null)
            {
                // Ok first let's get the private key filename
                string PrivateKeyFileName = Path.GetFileName(c.PrivateKeyFile.FileName);

                // Set the file path
                string PrivateKeyFilePath = Path.Combine(CredentialsRoot, PrivateKeyFileName);

                // Write from memory to disk
                using (var stream = new FileStream(PrivateKeyFilePath, FileMode.Create))
                {
                    await c.PrivateKeyFile.CopyToAsync(stream);
                }

                // If the private key file isn't a .ppk, convert it
                if (PrivateKeyFileName.Contains(".ppk"))
                {
                    // Ok it's the right type already
                    c.PrivateKeyFilePath = PrivateKeyFilePath;
                }
                else
                {
                    // Convert and return the path; set it against the cred object
                    if (String.IsNullOrEmpty(c.PrivateKeyPassphrase))
                    {
                        c.PrivateKeyFilePath = Tools.ConvertOpenSshKeyToPpk(PrivateKeyFilePath, PrivateKeyFileName, "");
                    }
                    else
                    {
                        c.PrivateKeyFilePath = Tools.ConvertOpenSshKeyToPpk(PrivateKeyFilePath, PrivateKeyFileName, c.PrivateKeyPassphrase);
                    }
                }
            }

            // Add the credentials to the credentialcache
            CredentialsCache.Add(c);

            // And redirect back to our hosts page
            return RedirectToAction("Credentials");
        }

        // Method for mitigating Microsoft's browsers being stupid
        public IActionResult GetTemplate()
        {
            // Declare the template structure and byte array it
            string TemplateData = "Endpoint,Operand,Tags\r\n";
            byte[] TemplateBytes = Encoding.ASCII.GetBytes(TemplateData);
            
            // Get our attachment content-disposition sorted
            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = "Audit-Hosts-Template.csv",
                Inline = true,
            };

            // Add the cd response header and return the stream
            Response.Headers.Add("Content-Disposition", cd.ToString());
            return File(TemplateBytes, "application/text");
        }

        // Method for calling the scan start
        public IActionResult StartScan()
        {
            // Reinitialise the scan object
            CurrentScan = new Scan();
            CurrentScan.Name = GlobalScanName;

            // Clear the hosts queue of completed hosts
            var HostsToClear = HostsCache.Where(c => c.Status == 3);
            HostsToClear.ToList().ForEach(htr => HostsCache.Remove(htr));

            // Thread off the task
            Task.Factory.StartNew(() => Audit.Scan());

            // Wait for the scan to start to ensure page loads correctly
            while (!CurrentScan.InProgress)
            {
                System.Threading.Thread.Sleep(500);
            }

            // And redirect back to our scan page
            return RedirectToAction("Scan", CurrentScan);
        }

        // Method for updating the scan progress
        public IActionResult RefreshResults()
        {
            return PartialView("ScanInfo", CurrentScan);
        }

        // Method for shutting down the container
        public IActionResult ShutdownContainer()
        {
            // Quick cleanup in case someone runs the container without the --rm switch
            Directory.Delete(CredentialsRoot);
            Directory.Delete(HostsRoot);
            Directory.Delete(ResultsRoot);
            Directory.Delete(DataRoot);

            // Begin the shutdown process and return the shutdown view
            Process.Start(@"C:\Windows\System32\shutdown.exe", "-s -t 1");
            return View("ShutdownMessage");
        }

        // Method for exporting data
        public IActionResult ExportData()
        {
            // Ok first let's zip up all the files
            string ZipFileName = String.Format("{0}-data.zip", GlobalScanName.ToLower());
            string ZipFilePath = Path.Combine(StorageRoot, ZipFileName);
            ZipFile.CreateFromDirectory(ResultsRoot, ZipFilePath, CompressionLevel.Fastest, false);

            // Read up the bytes from the exported zip file and remove it
            byte[] UnencryptedBytes = System.IO.File.ReadAllBytes(ZipFilePath);
            System.IO.File.Delete(ZipFilePath);

            // Get our export bytes array declared
            byte[] ExportBytes;
            
            // Get our memory stream to hold our exported data
            using (MemoryStream ExportStream = new MemoryStream())
            {
                // Our Rijndael provider
                RijndaelManaged R = new RijndaelManaged();

                // Use a cryptostream to encrypt the data
                using (CryptoStream cs = new CryptoStream(ExportStream,R.CreateEncryptor(RijndaelKey,RijndaelIV),CryptoStreamMode.Write))
                {
                    // Import the file and write to the cryptostream
                    using (MemoryStream ImportStream = new MemoryStream(UnencryptedBytes))
                    {
                        int data;
                        while ((data = ImportStream.ReadByte()) != -1)
                        {
                            cs.WriteByte((byte)data);
                        }
                    }

                    // Stream up the encrypted content for the client download
                    ExportBytes = ExportStream.ToArray();
                }
            }

            // Get our attachment content-disposition sorted
            var cd = new System.Net.Mime.ContentDisposition
            {
                FileName = String.Format("{0}-export.auditdata", GlobalScanName.ToLower()),
                Inline = true,
            };

            // Add the cd response header and return the stream
            Response.Headers.Add("Content-Disposition", cd.ToString());
            return File(ExportBytes, "application/octet-stream");
        }

    }

    // Tools class
    public static class Tools 
    {
        // Converts a given OpenSSH key into a putty private key (ppk) file
        public static string ConvertOpenSshKeyToPpk(string PrivateKeyFilePath, string PrivateKeyFileName, string PrivateKeyPassphrase) 
        {
            // Generate the outfile path and empty args string
            string OutputFilePath = String.Format(@"{0}\{1}.ppk", AuditController.CredentialsRoot, PrivateKeyFileName);
            string ConversionArgs = "";

            // If the passphrase is blank don't add to the args
            if (String.IsNullOrEmpty(PrivateKeyPassphrase))
            {
                ConversionArgs = String.Format("/keygen {0} /output={1}", PrivateKeyFilePath, OutputFilePath);
            }
            else 
            {
                ConversionArgs = String.Format("/keygen {0} /output={1} /passphrase={2}",PrivateKeyFilePath,OutputFilePath,PrivateKeyPassphrase);
            }

            // Transform to ppk
            Process.Start(@"C:\Program Files (x86)\WinSCP\WinSCP.com", ConversionArgs);
            
            // Return the path
            return OutputFilePath;
        }

        // Converts a cidr block to an IP range
        public static List<string> CidrToIpRange(string cidr)
        {
            // Ok split out our cidr into an array
            string[] parts = cidr.Split('.', '/');

            // Convert the IP portion to uint
            uint ipnum = (Convert.ToUInt32(parts[0]) << 24) |
                (Convert.ToUInt32(parts[1]) << 16) |
                (Convert.ToUInt32(parts[2]) << 8) |
                Convert.ToUInt32(parts[3]);

            // Calculate the mask bits based on the cidr number
            int maskbits = Convert.ToInt32(parts[4]);
            uint mask = 0xffffffff;
            mask <<= (32 - maskbits);

            // Get the start and end addresses
            uint ipstart = ipnum & mask;
            uint ipend = ipnum | (mask ^ 0xffffffff);

            // Create an arraylist to hold our IP range
            List<string> ips = new List<string>();

            // Enumerate using a for loop based on our start/end addresses
            for (uint ip = ipstart; ip <= ipend; ip++)
            {
                // Exclude 0 and 255 fourth octets
                if ((ip & 0xff) != 0 && (ip & 0xff) != 255)
                {
                    // Add our IP in string format to the array
                    ips.Add(String.Format("{0}.{1}.{2}.{3}", ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff));
                }
            }

            // And return the array
            return ips;
        }

        // Creates and adds a host object to the hosts cache
        public static void AddHostToCache(string[] Properties)
        {
            // Create a new host and set some properties
            Host h = new Host();
            h.ID = Guid.NewGuid().ToString();
            h.Endpoint = Properties[0];
            h.Operand = Properties[1];
            h.Status = 0;
            
            // Tags need parsing if present
            if (!String.IsNullOrEmpty(Properties[2]))
            {
                // Split up the string into tokens
                string[] tokens = Properties[2].Split('|');

                // Enumerate the tokens and process them
                foreach (string token in tokens)
                {
                    // Split the token into key:value
                    string[] pair = token.Split('=');

                    // Create the new key value pair
                    KeyValuePair<string,string> k = new KeyValuePair<string, string>(pair[0],pair[1]);

                    // Add a new pair to the host object
                    h.Tags.Add(k);
                }
            }

            // Add the host to the host cache
            AuditController.HostsCache.Add(h);
        }
    }

    // Audit class
    public static class Audit
    {
        // Synchronous scan worker method
        public static void Scan()
        {
            try 
            {
                // Ok we need to set some scan properties
                AuditController.CurrentScan.InProgress = true;
                AuditController.CurrentScan.Status = 1;
                AuditController.CurrentScan.TotalHostsCount = AuditController.HostsCache.Count;

                // Wipe any current errors we have for the hosts
                AuditController.HostsCache.Where(e => e.Errors.Count > 0).ToList().ForEach(er => er.Errors.Clear());

                // Filter our hosts list to place preference on any exclusions
                var HostsToInclude = AuditController.HostsCache.Where(i => i.Operand == ">" && 
                    (AuditController.HostsCache.Count(e => e.Operand == "<" && i.Endpoint == e.Endpoint) == 0)
                ).ToList();

                // Serialise the hosts and credentials
                string HostsJson = JsonConvert.SerializeObject(HostsToInclude);
                string CredentialsJson = JsonConvert.SerializeObject(AuditController.CredentialsCache);

                // Write the data to disk because passing in would be too long
                string HostsOutput = Path.Combine(AuditController.DataRoot, "hosts.json");
                string CredsOutput = Path.Combine(AuditController.DataRoot, "creds.json");
                System.IO.File.WriteAllText(HostsOutput, HostsJson);
                System.IO.File.WriteAllText(CredsOutput, CredentialsJson);

                // Get our PowerShell directory and script path sorted
                string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string PowerShell = Path.Combine(WindowsDir, "System32", "WindowsPowerShell", "v1.0", "PowerShell.exe");
                string PowerShellScriptPath = Path.Combine(AuditController.PowerShellRoot, "Run-Audit.ps1");

                // Build our commands
                string u_PowerShellCommand = "& '{0}' '{1}' '{2}' '{3}';[Environment]::Exit($LASTEXITCODE);";
                string f_PowerShellCommand = String.Format(u_PowerShellCommand, PowerShellScriptPath, CredsOutput, HostsOutput, AuditController.StorageRoot);
                string u_PowerShellArgs = "-NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -Command \"{0}\""; 
                string f_PowerShellArgs = String.Format(u_PowerShellArgs, f_PowerShellCommand);

                // Populate our process start info
                AuditController.ScanProcessInfo.CreateNoWindow = false;
                AuditController.ScanProcessInfo.FileName = PowerShell;
                AuditController.ScanProcessInfo.Arguments = f_PowerShellArgs;
                AuditController.ScanProcessInfo.UseShellExecute = false;
                AuditController.ScanProcessInfo.RedirectStandardError = true;
                AuditController.ScanProcessInfo.RedirectStandardOutput = true;
                AuditController.ScanProcess.StartInfo = AuditController.ScanProcessInfo;

                // Start the scan
                AuditController.ScanProcess.Start();

                // Wait while the process is running and update the results
                while (!AuditController.ScanProcess.HasExited)
                {
                    // Grab the line from stdout
                    string s = AuditController.ScanProcess.StandardOutput.ReadLine();

                    // If the line starts with UPDATE: - parse it
                    if (!String.IsNullOrEmpty(s))
                    {
                        if (s.Contains("SCANUPDATE:"))
                        {
                            // Cast to a dynamic object so we can pluck out what we're after
                            dynamic u = JsonConvert.DeserializeObject<dynamic>(s.Replace("SCANUPDATE:",""));

                            // Time remaining
                            AuditController.CurrentScan.EstimatedSecondsRemaining = System.Convert.ToInt32(u.EstimatedSecondsRemaining);

                            // Probes
                            AuditController.CurrentScan.ProbeSuccessCount = System.Convert.ToInt32(u.ProbeSuccessCount);
                            AuditController.CurrentScan.ProbeFailedCount = System.Convert.ToInt32(u.ProbeFailedCount);
                        
                            // Audits
                            AuditController.CurrentScan.AuditQueueCount = System.Convert.ToInt32(u.AuditQueueCount);
                            AuditController.CurrentScan.AuditSuccessCount = System.Convert.ToInt32(u.AuditSuccessCount);
                            AuditController.CurrentScan.AuditFailedCount = System.Convert.ToInt32(u.AuditFailedCount);
                            
                        }
                        else if (s.Contains("HOSTUPDATE:"))
                        {
                            // Cast to a dynamic object so we can pluck out what we're after
                            dynamic u = JsonConvert.DeserializeObject<dynamic>(s.Replace("HOSTUPDATE:",""));

                            // Update the host with the current info
                            AuditController.HostsCache.Where(h => h.ID == u.ID.ToString()).ToList().ForEach(htu => 
                                {
                                    htu.Status = u.Status;
                                    if (u.Errors != null) {
                                        foreach (string e in u.Errors){
                                            htu.Errors.Add(e);
                                        };
                                    }
                                }
                            );
                        }
                        else
                        {
                            // 's just another loop, man. ¯\_(ツ)_/¯
                        }
                    }
                }

                // If the exit code is non zero, grab the error and update the scan info
                if (AuditController.ScanProcess.ExitCode > 1)
                {
                    AuditController.CurrentScan.Status = 2;
                    AuditController.CurrentScan.ScanError = AuditController.ScanProcess.StandardError.ReadToEnd();
                }
                else
                {
                    // Ok we're completed ok but let's check and see whether there were any host errors
                    if (AuditController.HostsCache.Count(h => h.Errors.Count > 0) > 0)
                    {
                        AuditController.CurrentScan.Status = 4;
                    }
                    else
                    {
                        AuditController.CurrentScan.Status = 3;
                    }
                }

                // Stop the scan and close the process
                AuditController.CurrentScan.InProgress = false;
                AuditController.ScanProcess.Close();

            }
            catch (Exception e)
            {
                // Set the scan error and info
                AuditController.CurrentScan.Status = 2;
                AuditController.CurrentScan.InProgress = false;
                AuditController.CurrentScan.ScanError = e.ToString();

                // Make sure we close the process
                if (!AuditController.ScanProcess.HasExited) {
                    AuditController.ScanProcess.Close();
                }
            }
        }
    }

    // Credentials class
    public class Credential
    {
        public string ID {get; set;}
        public string Type {get; set;}
        public bool IsDefault {get; set;}
        public string Domain {get; set;}
        public string Username {get; set;}
        public string Password {get; set;}
        public IFormFile PrivateKeyFile {get; set;}
        public string PrivateKeyFilePath {get; set;}
        public string PrivateKeyPassphrase {get; set;}
    }

    // Host class
    public class Host
    {
        // Properties
        public string ID {get; set;}
        public string Endpoint {get; set;}
        public string Operand {get; set;}
        public List<KeyValuePair<string,string>> Tags = new List<KeyValuePair<string,string>>();
        public int Status {get; set;}
        public List<string> Errors = new List<string>();

        // Easy inline return of status text
        public string StatusString
        {
            get
            {
            // Get our status string together and work out the result
            string status = "";
            switch (this.Status)
            {
                case 0: {
                    status = "New";
                    break;
                }
                case 1: {
                    status = "Probe in progress";
                    break;
                }
                case 2: {
                    status = "Audit in progress";
                    break;
                }
                case 3: {
                    status = "Completed";
                    break;
                }
                case 101: {
                    status = "Probe error";
                    break;
                }
                case 201: {
                    status = "Audit error";
                    break;
                }
                case 202: {
                    status = "Audit Completed with Errors";
                    break;
                }
                case 999: {
                    status = "Non existent host";
                    break;
                }
            }

            // And return the result
            return status;
            }
        }

        // Returns a list of tags for the host
        public List<string> TagsList
        {
            get
            {
                // Get an output string sorted
                List<string> TagStrings = new List<string>();

                // Enumerate the tags list and build the string
                foreach (KeyValuePair<string,string> k in Tags)
                {
                    TagStrings.Add(String.Format("[{0} = {1}]", k.Key, k.Value));
                }

                // And return
                return TagStrings;
            }
        }
    }

    // Class to hold all information about the current scan
    public class Scan
    {
        // Basic properties
        public string Name {get; set;}
        public bool InProgress {get; set;}
        public int TotalHostsCount {get; set;}
        public string ScanError {get; set;}
        
        // Status
        public int Status {get; set;}
        public string StatusString
        {
            get
            {
                // Get our status string together and work out the result
                string status = "";
                switch (Status)
                {
                    case 0: {
                        status = "Not Running";
                        break;
                    }
                    case 1: {
                        status = "In Progress";
                        break;
                    }
                    case 2: {
                        status = "Scan Failed";
                        break;
                    }
                    case 3: {
                        status = "Completed Successfully";
                        break;
                    }
                    case 4: {
                        status = "Completed with Errors";
                        break;
                    }
                }

                // And return the result
                return status;
            }
        }
        
        // Total progress
        public int RemainingHostsCount
        {
            get
            {
                return (TotalHostsCount - CompletedHostsCount);
            }
        }
        public int CompletedHostsCount
        {
            get
            {
                return AuditCompletedCount;
            }
        }
        public int CompletedHostsPercent
        {
            get
            {
                int p = GetPercent(CompletedHostsCount, TotalHostsCount);

                if (p < 0)
                {
                    return 0;
                }
                else
                {
                    return p;
                }
            }
        }

        // Time remaining
        public int EstimatedSecondsRemaining {get; set;}
        public string TimeRemaining
        {
            get
            {
                TimeSpan t = TimeSpan.FromSeconds(EstimatedSecondsRemaining);
                return t.ToString(@"hh\:mm\:ss");
            }
        }

        // Probes total
        public int ProbeQueueCount
        {
            get
            {
                return TotalHostsCount;
            }
        }

        // Successful probes
        public int ProbeSuccessCount {get; set;}
        public int ProbeSuccessPercent
        {
            get
            {
                return GetPercent(ProbeSuccessCount, ProbeQueueCount);
            }
        }

        // Failed probes
        public int ProbeFailedCount {get; set;}
        public int ProbeFailedPercent
        {
            get
            {
                return GetPercent(ProbeFailedCount, ProbeQueueCount);
            }
        }

        // Remaining probes
        public int ProbeRemainingCount
        {
            get
            {
                return (ProbeQueueCount - ProbeCompletedCount);
            }
        }
        public int ProbeRemainingPercent
        {
            get
            {
                return GetPercent(ProbeRemainingCount, ProbeQueueCount);
            }
        }

        // Completed probes
        public int ProbeCompletedCount
        {
            get
            {
                return (ProbeSuccessCount + ProbeFailedCount);
            }
        }

        // Audits total
        public int AuditQueueCount {get; set;}

        // Successful audits
        public int AuditSuccessCount {get; set;}
        public int AuditSuccessPercent
        {
            get
            {
                return GetPercent(AuditSuccessCount, AuditQueueCount);
            }
        }

        // Failed audits
        public int AuditFailedCount {get; set;}
        public int AuditFailedPercent
        {
            get
            {
                return GetPercent(AuditFailedCount, AuditQueueCount);
            }
        }

        // Remaining audits
        public int AuditRemainingCount
        {
            get
            {
                return (AuditQueueCount - AuditCompletedCount);
            }
        }
        public int AuditRemainingPercent
        {
            get
            {
                return GetPercent(AuditRemainingCount, AuditQueueCount);
            }
        }

        // Completed audits
        public int AuditCompletedCount
        {
            get
            {
                return (AuditSuccessCount + AuditFailedCount);
            }
        }

        // Internal worker method for calculating percentages
        private int GetPercent(int Current, int Total)
        {
            return (int)Math.Round((double)(100 * Current) / Total);
        }
    }
    
}