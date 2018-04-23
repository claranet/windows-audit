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

namespace claranet_audit.Controllers
{
    // Mv controller
    public class AuditController : Controller
    {
        //////// Global Objects ////////

        // Storage paths
        public static readonly string StorageRoot = Path.Combine(Directory.GetCurrentDirectory(),"Audit");
        public static readonly string EncryptionRoot = Path.Combine(StorageRoot,"Encryption");
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
        private static string PublicKeyFilePath = "";
        private static string PrivateKeyFilePath = "";


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
                // Set our global scan name
                CurrentScan.Name = ScanName;
                GlobalScanName = ScanName;

                // Init the key paths from the global storage root and scan name
                PublicKeyFilePath = String.Format(@"{0}\{1}.pub",EncryptionRoot,ScanName);
                PrivateKeyFilePath = String.Format(@"{0}\{1}.auditkey",EncryptionRoot,ScanName);
                
                // Generate an asymmetric key pair and clear the first run flag
                Tools.GenerateAsymmetricKeyPair(PublicKeyFilePath, PrivateKeyFilePath);
                IsFirstRun = false;

                // Get the private key file bytes and delete the on-disk file
                byte[] PrivateKeyBytes = System.IO.File.ReadAllBytes(PrivateKeyFilePath);
                System.IO.File.Delete(PrivateKeyFilePath);
                
                // Get our attachment content-disposition sorted
                var cd = new System.Net.Mime.ContentDisposition
                {
                    FileName = String.Format("{0}.auditkey",ScanName),
                    Inline = true,
                };

                // Add the cd response header and return the stream
                Response.Headers.Add("Content-Disposition", cd.ToString());
                return File(PrivateKeyBytes, "application/text");
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
            string TemplateData = "Endpoint,Operand,Credential,OperatingSystem\r\n";
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

        // Returns an asymmetric key as XML
        public static string ConvertKeyToXml(RSACryptoServiceProvider rsa, bool ExportPrivateParameters)
        {
            // Get the properties
            RSAParameters p = rsa.ExportParameters(ExportPrivateParameters);

            // And return the string
            return String.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                            p.Modulus != null ? Convert.ToBase64String(p.Modulus) : null,
                            p.Exponent != null ? Convert.ToBase64String(p.Exponent) : null,
                            p.P != null ? Convert.ToBase64String(p.P) : null,
                            p.Q != null ? Convert.ToBase64String(p.Q) : null,
                            p.DP != null ? Convert.ToBase64String(p.DP) : null,
                            p.DQ != null ? Convert.ToBase64String(p.DQ) : null,
                            p.InverseQ != null ? Convert.ToBase64String(p.InverseQ) : null,
                            p.D != null ? Convert.ToBase64String(p.D) : null);
        }

        // Generates the asymmetric key pair for encrypting results
        public static void GenerateAsymmetricKeyPair(string PublicKeyPath, string PrivateKeyPath)
        {
            // Configure crypto service provider params
            CspParameters CspParams = new CspParameters();
            CspParams.ProviderType = 1;
            CspParams.Flags = CspProviderFlags.UseArchivableKey;
            CspParams.KeyNumber = (int)KeyNumber.Exchange;

            // Init the provider
            RSACryptoServiceProvider Rsa = new RSACryptoServiceProvider(CspParams);

            // Convert public key to xml string and write to file
            using (StreamWriter PublicKeyFile = System.IO.File.CreateText(PublicKeyPath)) 
            {
                PublicKeyFile.Write(ConvertKeyToXml(Rsa, false));
            }

            // Convert private key to xml string and write to file
            using (StreamWriter PrivateKeyFile = System.IO.File.CreateText(PrivateKeyPath)) 
            {
                PrivateKeyFile.Write(ConvertKeyToXml(Rsa, true));
            }
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
            
            // Credential needs parsing
            if (String.IsNullOrEmpty(Properties[2]))
            {
                h.Credential = "(Default)";
            }
            else
            {
                h.Familiarity += 10;
                h.Credential = Properties[2];
            }
            
            // OperatingSystem needs parsing
            if (String.IsNullOrEmpty(Properties[3]))
            {
                h.OperatingSystem = "Unknown (Initial)";
            }
            else
            {
                h.Familiarity += 100;
                h.OperatingSystem = Properties[3];
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
            // Ok we need to set some scan properties
            AuditController.CurrentScan.InProgress = true;
            AuditController.CurrentScan.Status = 1;
            AuditController.CurrentScan.TotalHostsCount = 100; // Should be AuditController.HostsCache.Count;

            // Filter our hosts list
            //var Includes = AuditController.HostsCache.Where(h => h.Operand == "Include").Select(e => e.Endpoint);
            //var Excludes = AuditController.HostsCache.Where(h => h.Operand == "Exclude").Select(e => e.Endpoint);
            //var HostEndpoints = Includes.Except(Excludes);

            // Serialise the hosts and credentials
            string HostsJson = JsonConvert.SerializeObject(AuditController.HostsCache);
            string CredentialsJson = JsonConvert.SerializeObject(AuditController.CredentialsCache);

            // Write the data to disk because passing in would be too long
            string HostsOutput = Path.Combine(AuditController.DataRoot, "hosts.json");
            string CredsOutput = Path.Combine(AuditController.DataRoot, "creds.json");
            System.IO.File.WriteAllText(HostsOutput, HostsJson);
            System.IO.File.WriteAllText(CredsOutput, CredentialsJson);

            // Build our command string
            string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string PowerShell = Path.Combine(WindowsDir, "System32", "WindowsPowerShell", "v1.0", "PowerShell.exe");
            
            string PowerShellScriptPath = Path.Combine(AuditController.PowerShellRoot, "Run-Audit.ps1");
            string u_PowerShellArgs = "-NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -Command \"& '{0}' '{1}' '{2}'"; 
            string f_PowerShellArgs = String.Format(u_PowerShellArgs, PowerShellScriptPath, CredsOutput, HostsOutput);

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
                        AuditController.CurrentScan.EstimatedSecondsRemaining = u.EstimatedSecondsRemaining;

                        // Probes
                        AuditController.CurrentScan.ProbeSuccessCount = u.ProbeSuccessCount;
                        AuditController.CurrentScan.ProbeFailedCount = u.ProbeFailedCount;
                       
                        // Audits
                        AuditController.CurrentScan.AuditQueueCount = u.AuditQueueCount;
                        AuditController.CurrentScan.AuditSuccessCount = u.AuditSuccessCount;
                        AuditController.CurrentScan.AuditFailedCount = u.AuditFailedCount;
                        
                    }
                    else if (s.Contains("HOSTUPDATE:"))
                    {
                        // Cast to a dynamic object so we can pluck out what we're after
                        dynamic u = JsonConvert.DeserializeObject<dynamic>(s.Replace("HOSTUPDATE:",""));

                        // Update the host with the current info
                        AuditController.HostsCache.Where(h => h.ID == u.ID).ToList().ForEach(htu => 
                            {
                                htu.Status = u.Status;
                                htu.Errors = u.Errors;
                            }
                        );
                    }
                    else
                    {
                        // ¯\_(ツ)_/¯
                    }
                }
            }

            // If the exit code is non zero, grab the error and update the scan info
            if (AuditController.ScanProcess.ExitCode > 0)
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
        public string Credential {get; set;}
        public string OperatingSystem {get; set;}
        public int Familiarity {get; set;}
        public int Status {get; set;}
        public List<string> Errors = new List<string>();
        public string AuditDataFilePath {get; set;}

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
            }

            // And return the result
            return status;
            }
        }

        // Easy inline return of familiarity text
        public string FamiliarityString
        {
            get
            {
                // Get our familiarity string together and work out the result
                string familiarity = "";
                switch (this.Familiarity)
                {
                    case 0: {
                        familiarity = "Unknown";
                        break;
                    }
                    case 10: {
                        familiarity = "Partially known (Auth)";
                        break;
                    }
                    case 100: {
                        familiarity = "Partially known (Type)";
                        break;
                    }
                    case 110: {
                        familiarity = "Well known";
                        break;
                    }
                }

                // And return the result
                return familiarity;
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