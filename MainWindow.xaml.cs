using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Management;

namespace SampleGroundForTheDay
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml   
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly HttpClient _httpClient = new HttpClient();
        private Button ScanButton;
        private ProgressBar ProgressBar;
        private TextBox StatusTextBlock; // Reference the RichTextBox control

        private readonly string quarantineFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Quarantine");

        private string quarantineFolderPath = @"C:\Quarantine"; // Specify the path to the quarantine folder

        private ManagementEventWatcher watcher;



        public MainWindow()
        {
            InitializeComponent();

            KeepButton.Click += KeepButton_Click;
            HardResetButton.Click += HardResetButton_Click;

            LogQuarantinedFiles();



            ScanButton = FindName("ScanButtonn") as Button;
            ProgressBar = FindName("ProgressBarr") as ProgressBar;
            StatusTextBox = FindName("StatusTextBox") as TextBox;
            LogTextBox = FindName("LogTextBox") as TextBox;
            ClearLogButton = FindName("ClearLogButton") as Button;

            ClearLogButton.IsEnabled = false; // Initially disable clear button

            LogConnectedRemovableDrives();

            watcher = new ManagementEventWatcher();
            watcher.Query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
            watcher.EventArrived += (sender, e) =>
            {
                int eventType = Convert.ToInt32(e.NewEvent.GetPropertyValue("EventType"));
                string driveName = e.NewEvent.GetPropertyValue("DriveName").ToString();

                if (eventType == 2) // Drive inserted
                {
                    LogTextBox.Dispatcher.Invoke(() =>
                    {
                        LogTextBox.AppendText($"Drive detected: {driveName}\n");
                    });
                }
                else if (eventType == 3) // Drive removed
                {
                    LogTextBox.Dispatcher.Invoke(() =>
                    {
                        LogTextBox.AppendText($"Drive removed: {driveName}\n");
                    });
                }
            };
            watcher.Start();

            Closed += MainWindow_Closed;
        }

        private void LogConnectedRemovableDrives()
        {
            var drives = DriveInfo.GetDrives().Where(drive => drive.DriveType == DriveType.Removable);
            foreach (var drive in drives)
            {
                string driveInfo = $"Drive detected: {drive.Name}\n";
                LogTextBox.AppendText($"{driveInfo}\n");
            }
        }
        private void MainWindow_Closed(object sender, EventArgs e)
        {
            if (watcher != null)
            {
                watcher.Stop();
                watcher.Dispose();
            }
        }
        private void EnsureQuarantineFolderExists()
        {
            if (!Directory.Exists(quarantineFolderPath))
            {
                Directory.CreateDirectory(quarantineFolderPath);

                // Make the folder hidden
                File.SetAttributes(quarantineFolderPath, File.GetAttributes(quarantineFolderPath) | FileAttributes.Hidden);

                // Remove read and execute permissions
                DirectoryInfo directoryInfo = new DirectoryInfo(quarantineFolderPath);
                DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();
                directorySecurity.AddAccessRule(new FileSystemAccessRule(Environment.UserName, FileSystemRights.ReadAndExecute, AccessControlType.Deny));
                directoryInfo.SetAccessControl(directorySecurity);
            }
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Replace with your actual API key
                string apiKey = "00fc286349bdbca1e47b6e78a07cc4791195a230d4f64a44421c6726a5126354";

                // Scan for removable drives
                var drives = DriveInfo.GetDrives().Where(drive => drive.DriveType == DriveType.Removable);

                ClearLog(); // Clear log before scanning

                StatusTextBox.Text = "Scanning flash drive...";
                ProgressBar.Visibility = Visibility.Visible;

                int totalFilesScanned = 0;
                int totalFiles = drives.Sum(drive => Directory.GetFiles(drive.Name, "*.*", SearchOption.AllDirectories).Length);

                foreach (var drive in drives)
                {
                    string driveLetter = drive.Name;
                    var files = Directory.EnumerateFiles(driveLetter, "*.*", SearchOption.AllDirectories);

                    foreach (var file in files)
                    {
                        totalFilesScanned++;

                        string fileHash = GetFileHash(file);
                        bool isSuspicious = await CheckFileHash(apiKey, fileHash, file); // Pass the file path here

                        LogTextBox.AppendText($"{file}: {(isSuspicious ? "Suspicious" : "Clean")}\n");

                        // Update progress bar
                        double progress = (double)totalFilesScanned / totalFiles * 100;
                        ProgressBar.Value = progress;
                    }
                }

                ProgressBar.Visibility = Visibility.Collapsed;
                StatusTextBox.Text = $"Scan complete. Scanned {totalFilesScanned} files.";

                // Enable clear button only if there are log entries
                ClearLogButton.IsEnabled = LogTextBox.Text.Length > 0;
            }
            catch (Exception ex)
            {
                StatusTextBox.Text = $"Error: {ex.Message}";
                MessageBox.Show($"Error occurred during scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }



        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            ClearLog();
        }
        private void ClearLog()
        {
            LogTextBox.Clear();
            StatusTextBox.Text = "Ready to scan.";
            ClearLogButton.IsEnabled = false; // Disable clear button after clearing
        }

        private string GetFileHash(string filePath)
        {
            using (var stream = File.OpenRead(filePath))
            {
                var sha256 = SHA256.Create();
                var hashBytes = sha256.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        private async Task<bool> CheckFileHash(string apiKey, string fileHash, string filePath)
        {
            if (Path.GetExtension(filePath).Equals(".bat", StringComparison.OrdinalIgnoreCase))
            {
                // Mark .bat files as suspicious without checking with VirusTotal
                QuarantineFile(filePath);
                return true;
            }

            string url = $"https://www.virustotal.com/api/v3/files/{fileHash}";

            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                request.Headers.Add("x-apikey", apiKey);

                using (var response = await _httpClient.SendAsync(request))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        string content = await response.Content.ReadAsStringAsync();
                        var data = JsonSerializer.Deserialize<Dictionary<string, object>>(content);

                        if (data.ContainsKey("positives"))
                        {
                            int positives = Convert.ToInt32(data["positives"]);
                            if (positives > 0)
                            {
                                QuarantineFile(filePath);
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }
        private void QuarantineFile(string filePath)
        {
            string quarantineFilePath = Path.Combine(quarantineFolder, Path.GetFileName(filePath));

            try
            {
                if (!Directory.Exists(quarantineFolder))
                {
                    Directory.CreateDirectory(quarantineFolder);
                }

                File.Move(filePath, quarantineFilePath);

                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Quarantined suspicious file: {filePath}\n");
                });

                // Append quarantined file information to QuarantineTextBox
                QuarantineTextBox.Dispatcher.Invoke(() =>
                {
                    QuarantineTextBox.AppendText($"Quarantined: {quarantineFilePath}\n");
                });
            }
            catch (Exception ex)
            {
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Error quarantining file {filePath}: {ex.Message}\n");
                });
            }
        }



        private bool PromptDelete(string filePath)
        {
            var result = MessageBox.Show($"A suspicious file was detected: {filePath}\nDo you want to delete it?", "Suspicious File Detected", MessageBoxButton.YesNo, MessageBoxImage.Question);
            return result == MessageBoxResult.Yes;
        }
        private void DeleteFile(string filePath)
        {
            try
            {
                File.Delete(filePath);
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Deleted suspicious file: {filePath}\n");
                });

                // Show a message box indicating that the file has been deleted
                MessageBox.Show($"Deleted suspicious file: {filePath}", "File Deleted", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Error deleting file {filePath}: {ex.Message}\n");
                });
            }
        }


        private void CleanButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to clean all quarantined files?", "Confirmation", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                string[] quarantinedFiles = QuarantineTextBox.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (string quarantinedFile in quarantinedFiles)
                {
                    string filePath = quarantinedFile.Substring("Quarantined: ".Length).Trim(); // Trim to remove leading and trailing whitespaces
                    DeleteFile(filePath);
                }
                QuarantineTextBox.Clear(); // Clear all entries from QuarantineTextBox
            }
        }

        public void LogQuarantinedFiles()
        {
            if (Directory.Exists(quarantineFolder))
            {
                var files = Directory.GetFiles(quarantineFolder);
                foreach (var file in files)
                {
                    QuarantineTextBox.AppendText($"Quarantined: {file}\n");
                }
            }
        }
        private void KeepButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to keep all quarantined files for 7 days?", "Confirmation", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                string[] quarantinedFiles = QuarantineTextBox.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (string quarantinedFile in quarantinedFiles)
                {
                    string filePath = quarantinedFile.Substring("Quarantined: ".Length).Trim(); // Trim to remove leading and trailing whitespaces
                    KeepFileFor7Days(filePath);
                }
                QuarantineTextBox.Clear(); // Clear all entries from QuarantineTextBox
            }
        }
        private async void KeepFileFor7Days(string filePath)
        {
            try
            {
                string quarantineFilePath = Path.Combine(quarantineFolder, Path.GetFileName(filePath));

                // Move the file to the quarantine folder if it's not already there
                if (!File.Exists(quarantineFilePath))
                {
                    File.Move(filePath, quarantineFilePath);
                }

                // Calculate the date 7 days from now
                DateTime deletionDate = DateTime.Now.AddDays(7);

                // Write the deletion date to a file in the quarantine folder
                string deletionDateFilePath = Path.Combine(quarantineFolder, $"{Path.GetFileNameWithoutExtension(filePath)}.delete");
                await File.WriteAllTextAsync(deletionDateFilePath, deletionDate.ToString());

                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"File {Path.GetFileName(filePath)} will be deleted on {deletionDate}\n");
                });
            }
            catch (Exception ex)
            {
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Error keeping file {Path.GetFileName(filePath)}: {ex.Message}\n");
                });
            }
        }
        private void HardResetButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure you want to hard reset the flash drive? This will permanently delete all files on the flash drive.", "Confirmation", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                string[] quarantinedFiles = QuarantineTextBox.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (string quarantinedFile in quarantinedFiles)
                {
                    string filePath = quarantinedFile.Substring("Quarantined: ".Length).Trim(); // Trim to remove leading and trailing whitespaces
                    RestoreFileToFlashDrive(filePath);
                }
                QuarantineTextBox.Clear(); // Clear all entries from QuarantineTextBox

                // Reformat the flash drive
                ReformatFlashDrive();
            }
        }

        private void RestoreFileToFlashDrive(string filePath)
        {
            try
            {
                string driveLetter = Path.GetPathRoot(filePath).Replace("\\", "");

                string quarantineFilePath = Path.Combine(quarantineFolder, Path.GetFileName(filePath));

                // Move the file back to the flash drive
                File.Move(quarantineFilePath, filePath);

                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Restored file {Path.GetFileName(filePath)} to flash drive {driveLetter}\n");
                });
            }
            catch (Exception ex)
            {
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Error restoring file {Path.GetFileName(filePath)}: {ex.Message}\n");
                });
            }
        }
        private void ReformatFlashDrive()
        {
            string[] drives = Directory.GetLogicalDrives();

            foreach (string drive in drives)
            {
                DriveInfo driveInfo = new DriveInfo(drive);

                if (driveInfo.DriveType == DriveType.Removable)
                {
                    try
                    {
                        using (var disk = new FileStream(drive, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                        {
                            disk.SetLength(0);
                        }

                        LogTextBox.Dispatcher.Invoke(() =>
                        {
                            LogTextBox.AppendText($"Reformatted flash drive {drive}\n");
                        });
                    }
                    catch (UnauthorizedAccessException)
                    {
                        LogTextBox.Dispatcher.Invoke(() =>
                        {
                            LogTextBox.AppendText($"Access denied. Run the application as administrator.\n");
                        });
                    }
                    catch (Exception ex)
                    {
                        LogTextBox.Dispatcher.Invoke(() =>
                        {
                            LogTextBox.AppendText($"Error reformatting flash drive {drive}: {ex.Message}\n");
                        });
                    }
                }
            }
        }



    }
}