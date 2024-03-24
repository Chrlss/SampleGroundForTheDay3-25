using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Windows.Controls;


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
        private RichTextBox StatusTextBlock; // Reference the RichTextBox control
        public MainWindow()
        {
            InitializeComponent();
            ScanButton = FindName("ScanButtonn") as Button;
            ProgressBar = FindName("ProgressBarr") as ProgressBar;
            StatusTextBox = FindName("StatusTextBox") as TextBox;
            LogTextBox = FindName("LogTextBox") as TextBox;
            ClearLogButton = FindName("ClearLogButton") as Button;

            ClearLogButton.IsEnabled = false; // Initially disable clear button
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

                StatusTextBox.Text = "Scanning flash drives...";
                ProgressBar.Visibility = Visibility.Visible;

                int totalFilesScanned = 0;

                foreach (var drive in drives)
                {
                    string driveLetter = drive.Name;
                    var files = Directory.EnumerateFiles(driveLetter, "*.*", SearchOption.AllDirectories);

                    foreach (var file in files)
                    {
                        totalFilesScanned++;
                        StatusTextBox.Text = $"Scanning files: {totalFilesScanned} total";

                        string fileHash = GetFileHash(file);
                        bool isSuspicious = await CheckFileHash(apiKey, fileHash);

                        LogTextBox.AppendText($"{file}: {(isSuspicious ? "Suspicious" : "Clean")}\n");

                        if (isSuspicious)
                        {
                            StatusTextBox.Text += $"[Warning] Suspicious file found: {file}\n";
                        }
                    }
                }

                ProgressBar.Visibility = Visibility.Collapsed;
                StatusTextBox.Text = "Scan complete.";

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

        private async Task<bool> CheckFileHash(string apiKey, string fileHash)
        {
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
                            return positives > 0;
                        }
                    }
                }
            }

            return false;
        }
    }
}