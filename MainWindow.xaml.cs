using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
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


        private ManagementEventWatcher watcher;
        public MainWindow()
        {
            InitializeComponent();
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
                if (PromptDelete(filePath))
                {
                    DeleteFile(filePath);
                    return true;
                }
                else
                {
                    return false;
                }
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
                                if (PromptDelete(filePath))
                                {
                                    DeleteFile(filePath);
                                    return true;
                                }
                                else
                                {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }

            return false;
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
            }
            catch (Exception ex)
            {
                LogTextBox.Dispatcher.Invoke(() =>
                {
                    LogTextBox.AppendText($"Error deleting file {filePath}: {ex.Message}\n");
                });
            }
        }
    }
}