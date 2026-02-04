#requires -Version 5.1


$script:AppName    = "CFEM - Cloud File Encryption Manager"
$script:AppVersion = "2.6.1"
$script:BuildDate  = "2026-02-03"

<#

CFEM - Cloud File Encryption Manager
Copyright (c) 2026 Todd L.

Licensed under the MIT License.
See LICENSE file in the project root for full license information.

.SYNOPSIS
    CFEM - Cloud File Encryption Manager - Secure your cloud storage with AES-256 encryption

.DESCRIPTION
    Encrypts and decrypts files before they sync to cloud storage (OneDrive, Google Drive, Dropbox, etc.)
    Uses AES-256-CBC encryption with PBKDF2 key derivation for password-based encryption.
    Features:
    - Password-based encryption (AES-256)
    - Encrypt/decrypt files and folders
    - Batch operations
    - Auto-encryption monitoring
    - Secure file deletion
    - Integrity verification (HMAC)
    - Progress tracking

.NOTES
    Author: Todd L.
    Version: 1.0
    Requires: PowerShell 5.1+, .NET Framework 4.5+

#>

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security

#region XAML Definition

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="CFEM - Cloud File Encryption Manager" 
        Height="700" Width="1000"
        WindowStartupLocation="CenterScreen"
        Background="#F5F5F5">
    
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Foreground" Value="White"/>
        </Style>
        
        <Style TargetType="TextBlock">
            <Setter Property="Margin" Value="5"/>
        </Style>
        
        <Style TargetType="TextBox">
            <Setter Property="Padding" Value="5"/>
            <Setter Property="Margin" Value="5"/>
        </Style>
    </Window.Resources>
    
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <!-- Header -->
        <Border Grid.Row="0" Background="#2C3E50" CornerRadius="5" Padding="15" Margin="0,0,0,10">
            <StackPanel>
                <TextBlock Text="CFEM - Cloud File Encryption Manager" 
                          FontSize="24" FontWeight="Bold" Foreground="White"/>
                <TextBlock Text="Secure your cloud files with military-grade AES-256 encryption" 
                          FontSize="12" Foreground="#ECF0F1" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>
        
        <!-- Tab Control -->
        <TabControl Grid.Row="1" Grid.RowSpan="2" Margin="0,0,0,10">
            
            <!-- Encrypt/Decrypt Tab -->
            <TabItem Header="Encrypt/Decrypt">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Password Section -->
                    <Border Grid.Row="0" Background="White" BorderBrush="#BDC3C7" 
                            BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>
                            
                            <StackPanel Grid.Row="0" Orientation="Horizontal">
                                <TextBlock Text="Encryption Password:" FontWeight="Bold" 
                                          VerticalAlignment="Center" Width="150"/>
                                <PasswordBox Name="txtPassword" Width="300" Height="30" 
                                            VerticalContentAlignment="Center"/>
                                <TextBlock Text="(12+ characters recommended)" 
                                          VerticalAlignment="Center" Margin="10,0,0,0" 
                                          Foreground="#7F8C8D" FontSize="10"/>
                                <Button Name="btnShowPassword" Content="Show" Width="60" 
                                       Background="#95A5A6" Margin="10,0,0,0"/>
                            </StackPanel>
                            
                            <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,10,0,0">
                                <CheckBox Name="chkRememberPassword" Content="Remember password for this session" 
                                         VerticalAlignment="Center"/>
                                <TextBlock Text="[!] Not saved to disk" Foreground="#E67E22" 
                                          VerticalAlignment="Center" Margin="10,0,0,0" FontSize="10"/>
                            </StackPanel>
                        </Grid>
                    </Border>
                    
                    <!-- File Selection -->
                    <Border Grid.Row="1" Background="#E8F5E9" BorderBrush="#4CAF50" 
                            BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                        <StackPanel>
                            <TextBlock Text="Select Files/Folders to Encrypt or Decrypt" FontWeight="Bold"/>
                            <StackPanel Orientation="Horizontal" Margin="0,10,0,0">
                                <Button Name="btnSelectFiles" Content="Select Files" Width="140" Background="#2196F3"/>
                                <Button Name="btnSelectFolder" Content="Select Folder" Width="140" Background="#2196F3"/>
                                <Button Name="btnClearSelection" Content="Clear Selection" Width="140" Background="#95A5A6"/>
                                <TextBlock Name="txtSelectionCount" Text="0 items selected" 
                                          VerticalAlignment="Center" Margin="20,0,0,0" FontWeight="SemiBold"/>
                            </StackPanel>
                        </StackPanel>
                    </Border>
                    
                    <!-- File List -->
                    <Border Grid.Row="2" Background="White" BorderBrush="#BDC3C7" 
                            BorderThickness="1" CornerRadius="3" Padding="10" MinHeight="220">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <TextBlock Grid.Row="0" Text="Selected Files:" FontWeight="Bold" Margin="0,0,0,5"/>
                            
                            <ListView Name="lstFiles" Grid.Row="1" 
                                     SelectionMode="Extended" 
                                     BorderThickness="0" MinHeight="180">
                                <ListView.View>
                                    <GridView>
                                        <GridViewColumn Header="Status" Width="60">
                                            <GridViewColumn.CellTemplate>
                                                <DataTemplate>
                                                    <TextBlock Text="{Binding Status}" FontWeight="Bold"/>
                                                </DataTemplate>
                                            </GridViewColumn.CellTemplate>
                                        </GridViewColumn>
                                        <GridViewColumn Header="File Path" Width="500">
                                            <GridViewColumn.CellTemplate>
                                                <DataTemplate>
                                                    <TextBlock Text="{Binding Path}" ToolTip="{Binding Path}"/>
                                                </DataTemplate>
                                            </GridViewColumn.CellTemplate>
                                        </GridViewColumn>
                                        <GridViewColumn Header="Size" Width="100">
                                            <GridViewColumn.CellTemplate>
                                                <DataTemplate>
                                                    <TextBlock Text="{Binding Size}" TextAlignment="Right"/>
                                                </DataTemplate>
                                            </GridViewColumn.CellTemplate>
                                        </GridViewColumn>
                                        <GridViewColumn Header="Type" Width="150">
                                            <GridViewColumn.CellTemplate>
                                                <DataTemplate>
                                                    <TextBlock Text="{Binding Type}"/>
                                                </DataTemplate>
                                            </GridViewColumn.CellTemplate>
                                        </GridViewColumn>
                                    </GridView>
                                </ListView.View>
                            </ListView>
                        </Grid>
                    </Border>
                    
                    <!-- Action Buttons -->
                    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                        <Button Name="btnEncrypt" Content="Encrypt Selected" Width="180" Height="40" 
                               Background="#27AE60" FontSize="14"/>
                        <Button Name="btnDecrypt" Content="Decrypt Selected" Width="180" Height="40" 
                               Background="#3498DB" FontSize="14"/>
                        <Button Name="btnSecureDelete" Content="Secure Delete" Width="180" Height="40" 
                               Background="#E74C3C" FontSize="14"/>
                    </StackPanel>
                </Grid>
            </TabItem>
            
            <!-- Auto-Encrypt Tab -->
            <TabItem Header="Auto-Encrypt">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <!-- Auto-Encrypt Settings -->
                    <Border Grid.Row="0" Background="White" BorderBrush="#BDC3C7" 
                            BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                        <StackPanel>
                            <TextBlock Text="Automatic Encryption" FontSize="16" FontWeight="Bold"/>
                            <TextBlock Text="Monitor folders and automatically encrypt new files as they're created" 
                                      Foreground="#7F8C8D" Margin="0,5,0,15"/>
                            
                            <CheckBox Name="chkAutoEncryptEnabled" Content="Enable Auto-Encryption" 
                                     FontWeight="SemiBold" Margin="0,0,0,15"/>
                            
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                
                                <TextBlock Grid.Column="0" Text="Monitor Folder:" VerticalAlignment="Center" 
                                          Width="120" FontWeight="SemiBold"/>
                                <TextBox Name="txtMonitorFolder" Grid.Column="1" Height="30" 
                                        VerticalContentAlignment="Center" />
                                <Button Name="btnBrowseMonitor" Grid.Column="2" Content="Browse..." 
                                       Width="100" Background="#3498DB"/>
                            </Grid>
                        </StackPanel>
                    </Border>
                    
                    <!-- Filter Rules -->
                    <Border Grid.Row="1" Background="#FFF9E6" BorderBrush="#F39C12" 
                            BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                        <StackPanel>
                            <TextBlock Text="Encryption Filters" FontWeight="Bold"/>
                            <TextBlock Text="Only encrypt files matching these patterns (leave blank to encrypt all files)" 
                                      Foreground="#7F8C8D" FontSize="10" Margin="0,5,0,10"/>
                            
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height="Auto"/>
                                    <RowDefinition Height="Auto"/>
                                </Grid.RowDefinitions>
                                
                                <TextBlock Grid.Row="0" Grid.Column="0" Text="Include Extensions:" 
                                          VerticalAlignment="Center" Width="140"/>
                                <TextBox Name="txtIncludeExtensions" Grid.Row="0" Grid.Column="1" 
                                        Height="30" VerticalContentAlignment="Center"
                                        ToolTip="Example: .docx,.xlsx,.pdf (comma-separated)"/>
                                
                                <TextBlock Grid.Row="1" Grid.Column="0" Text="Exclude Extensions:" 
                                          VerticalAlignment="Center" Width="140"/>
                                <TextBox Name="txtExcludeExtensions" Grid.Row="1" Grid.Column="1" 
                                        Height="30" VerticalContentAlignment="Center"
                                        ToolTip="Example: .tmp,.temp,.bak (comma-separated)"/>
                            </Grid>
                        </StackPanel>
                    </Border>
                    
                    <!-- Monitor Log -->
                    <Border Grid.Row="2" Background="White" BorderBrush="#BDC3C7" 
                            BorderThickness="1" CornerRadius="3" Padding="10" MinHeight="220">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            
                            <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,5">
                                <TextBlock Text="Activity Log" FontWeight="Bold"/>
                                <Button Name="btnClearLog" Content="Clear Log" Width="100" 
                                       Background="#95A5A6" Margin="20,0,0,0" Height="25"/>
                            </StackPanel>
                            
                            <TextBox Name="txtAutoEncryptLog" Grid.Row="1" 
                                     
                                    TextWrapping="Wrap" 
                                    VerticalScrollBarVisibility="Auto"
                                    FontFamily="Consolas" 
                                    FontSize="10"
                                    Background="#FAFAFA"/>
                        </Grid>
                    </Border>
                    
                    <!-- Control Buttons -->
                    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                        <Button Name="btnStartMonitoring" Content="Start Monitoring" Width="180" Height="40" 
                               Background="#27AE60" FontSize="14" IsEnabled="False"/>
                        <Button Name="btnStopMonitoring" Content="Stop Monitoring" Width="180" Height="40" 
                               Background="#E74C3C" FontSize="14" IsEnabled="False"/>
                    </StackPanel>
                </Grid>
            </TabItem>
            
            <!-- Settings Tab -->
            <TabItem Header="Settings">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="10">
                        
                        <!-- Encryption Settings -->
                        <Border Background="White" BorderBrush="#BDC3C7" 
                                BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="Encryption Settings" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                                
                                <Grid Margin="0,0,0,10">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="200"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="Auto"/>
                                    </Grid.RowDefinitions>
                                    
                                    <TextBlock Grid.Row="0" Grid.Column="0" Text="Algorithm:" VerticalAlignment="Center"/>
                                    <ComboBox Name="cmbAlgorithm" Grid.Row="0" Grid.Column="1" Height="30" 
                                             IsEnabled="False">
                                        <ComboBoxItem Content="AES-256 (Recommended)" IsSelected="True"/>
                                    </ComboBox>
                                    
                                    <TextBlock Grid.Row="1" Grid.Column="0" Text="Key Derivation Iterations:" 
                                              VerticalAlignment="Center"/>
                                    <ComboBox Name="cmbIterations" Grid.Row="1" Grid.Column="1" Height="30">
                                        <ComboBoxItem Content="100,000 (Fast)" Tag="100000"/>
                                        <ComboBoxItem Content="250,000 (Balanced)" IsSelected="True" Tag="250000"/>
                                        <ComboBoxItem Content="500,000 (Secure)" Tag="500000"/>
                                        <ComboBoxItem Content="1,000,000 (Maximum Security)" Tag="1000000"/>
                                    </ComboBox>
                                    
                                    <TextBlock Grid.Row="2" Grid.Column="0" Text="Encrypted File Extension:" 
                                              VerticalAlignment="Center"/>
                                    <TextBox Name="txtEncryptedExtension" Grid.Row="2" Grid.Column="1" 
                                            Text=".encrypted" Height="30" VerticalContentAlignment="Center"/>
                                </Grid>
                                
                                <TextBlock Text="Higher iterations = More secure but slower encryption/decryption" 
                                          Foreground="#7F8C8D" FontSize="10"/>
                            </StackPanel>
                        </Border>
                        
                        <!-- File Handling -->
                        <Border Background="White" BorderBrush="#BDC3C7" 
                                BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="File Handling" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                                
                                <CheckBox Name="chkDeleteOriginal" Content="Delete original files after encryption" 
                                         Margin="0,5"/>
                                <CheckBox Name="chkSecureDelete" Content="Use secure delete (7-pass overwrite)" 
                                         Margin="0,5" IsChecked="True"/>
                                <CheckBox Name="chkDeleteEncrypted" Content="Delete encrypted files after decryption" 
                                         Margin="0,5"/>
                                <CheckBox Name="chkPreserveTimestamps" Content="Preserve original file timestamps" 
                                         Margin="0,5" IsChecked="True"/>
                                
                                <TextBlock Text="[!] Secure delete is slower but prevents file recovery" 
                                          Foreground="#E67E22" FontSize="10" Margin="0,10,0,0"/>
                            </StackPanel>
                        </Border>
                        
                        <!-- Default Folders -->
                        <Border Background="White" BorderBrush="#BDC3C7" 
                                BorderThickness="1" CornerRadius="3" Padding="15" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="Cloud Storage Folders" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                                
                                <CheckBox Name="chkOneDrive" Content="OneDrive" Margin="0,5"/>
                                <TextBox Name="txtOneDrivePath" Height="30" Margin="20,0,0,5" 
                                        VerticalContentAlignment="Center" />
                                
                                <CheckBox Name="chkGoogleDrive" Content="Google Drive" Margin="0,5"/>
                                <TextBox Name="txtGoogleDrivePath" Height="30" Margin="20,0,0,5" 
                                        VerticalContentAlignment="Center" />
                                
                                <CheckBox Name="chkDropbox" Content="Dropbox" Margin="0,5"/>
                                <TextBox Name="txtDropboxPath" Height="30" Margin="20,0,0,5" 
                                        VerticalContentAlignment="Center" />
                                                            
                                <CheckBox Name="chkSyncToCloud" Content="Sync newly encrypted outputs to selected cloud folders" Margin="0,10,0,0"/>
                                <StackPanel Orientation="Horizontal" Margin="20,5,0,0">
                                    <TextBlock Text="Cloud subfolder:" VerticalAlignment="Center" Foreground="#2C3E50"/>
                                    <TextBox Name="txtCloudSubfolder" Width="220" Height="26" Margin="10,0,0,0" VerticalContentAlignment="Center" Text="Encrypted"/>
                                </StackPanel>
</StackPanel>
                        </Border>
                        
                        <!-- Save Settings -->
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                            <Button Name="btnSaveSettings" Content="Save Settings" Width="150" 
                                   Background="#27AE60" FontSize="14"/>
                            <Button Name="btnResetSettings" Content="Reset to Defaults" Width="150" 
                                   Background="#95A5A6" FontSize="14"/>
                        </StackPanel>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>
            
            <!-- About Tab -->
            <TabItem Header="About">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="20">
                        <TextBlock Text="CFEM - Cloud File Encryption Manager" FontSize="24" FontWeight="Bold" 
                                  Margin="0,0,0,10"/>
                        <TextBlock Text="Version 1.0" FontSize="14" Foreground="#7F8C8D" Margin="0,0,0,20"/>
                        
                        <TextBlock Text="About This Tool" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                        <TextBlock TextWrapping="Wrap" Margin="0,0,0,20">
                            This tool encrypts your files before they sync to cloud storage services like OneDrive, 
                            Google Drive, and Dropbox. Your cloud provider can only see encrypted data - only you 
                            have the decryption password.
                        </TextBlock>
                        
                        <TextBlock Text="Security Features" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
                        <TextBlock TextWrapping="Wrap" Margin="0,0,0,5">
                            o AES-256 encryption (military-grade, industry standard)<LineBreak/>
                            o PBKDF2 key derivation with 250,000+ iterations<LineBreak/>
                            o Unique random IV (initialization vector) per file<LineBreak/>
                            o HMAC-SHA256 authentication (detects tampering)<LineBreak/>
                            o Secure password handling (never stored to disk)<LineBreak/>
                            o DOD 5220.22-M secure file deletion (7-pass overwrite)<LineBreak/>
                            o No backdoors or key escrow
                        </TextBlock>
                        
                        <TextBlock Text="How It Works" FontSize="16" FontWeight="Bold" Margin="0,20,0,10"/>
                        <TextBlock TextWrapping="Wrap" Margin="0,0,0,5">
                            1. You select files/folders to encrypt<LineBreak/>
                            2. Enter a strong password (12+ characters recommended)<LineBreak/>
                            3. Files are encrypted with AES-256 using your password<LineBreak/>
                            4. Encrypted files sync to your cloud storage<LineBreak/>
                            5. Cloud provider sees only encrypted gibberish<LineBreak/>
                            6. To decrypt, use the same password
                        </TextBlock>
                        
                        <TextBlock Text="[!] Important Security Notes" FontSize="16" FontWeight="Bold" 
                                  Margin="0,20,0,10" Foreground="#E74C3C"/>
                        <TextBlock TextWrapping="Wrap" Foreground="#E74C3C" Margin="0,0,0,5">
                            o Use a strong, unique password (12+ characters with mix of letters, numbers, symbols)<LineBreak/>
                            o DO NOT forget your password - there is NO password recovery<LineBreak/>
                            o Consider using a password manager<LineBreak/>
                            o Keep backups of important files before encryption<LineBreak/>
                            o This tool cannot decrypt files if you lose the password
                        </TextBlock>
                        
                        <TextBlock Text="Technical Details" FontSize="16" FontWeight="Bold" Margin="0,20,0,10"/>
                        <TextBlock TextWrapping="Wrap" FontFamily="Consolas" FontSize="10" 
                                  Background="#F8F8F8" Padding="10" Margin="0,0,0,5">
                            Algorithm: AES-256-CBC<LineBreak/>
                            Key Derivation: PBKDF2-HMAC-SHA256<LineBreak/>
                            Default Iterations: 250,000<LineBreak/>
                            Salt: 32 bytes (random per file)<LineBreak/>
                            IV: 16 bytes (random per file)<LineBreak/>
                            Authentication: HMAC-SHA256<LineBreak/>
                            File Format: [Salt 32][IV 16][HMAC 32][Encrypted Data]
                        </TextBlock>
                        
                        <TextBlock Text="License" FontSize="16" FontWeight="Bold" Margin="0,20,0,10"/>
                        <TextBlock TextWrapping="Wrap" Margin="0,0,0,20">
                            This tool is provided as-is for personal and commercial use. 
                            No warranty is provided. Use at your own risk.
                        </TextBlock>

                <TextBlock Name="txtHelpFooter" Text="" FontStyle="Italic" Foreground="#666666" Margin="0,10,0,0"/>
            </StackPanel>
                </ScrollViewer>
            </TabItem>
            
        </TabControl>
        
        <!-- Progress Bar -->
        <Border Grid.Row="3" Background="White" BorderBrush="#BDC3C7" 
                BorderThickness="1" CornerRadius="3" Padding="10" Margin="0,0,0,10">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                
                <StackPanel Grid.Row="0" Orientation="Horizontal">
                    <TextBlock Name="txtProgressStatus" Text="Ready" FontWeight="SemiBold"/>
                    <TextBlock Name="txtProgressDetail" Text="" Margin="20,0,0,0" Foreground="#7F8C8D"/>
                </StackPanel>
                
                    <ProgressBar Name="progressBar" Grid.Row="1" Height="20" Margin="0,5,0,0" 
                Minimum="0" Maximum="100" Value="0"/>

    <Expander Grid.Row="2" Header="Logs" Margin="0,10,0,0">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,5">
                <Button Name="btnOpenLogs" Content="Open Logs Folder" Width="140" Height="26"/>
                <Button Name="btnOpenCloudDest" Content="Open Cloud Destination" Width="170" Height="26" Margin="10,0,0,0"/>
                <TextBlock Text="(latest log updates below)" Margin="10,4,0,0" Foreground="#7F8C8D"/>
            </StackPanel>

            <TextBox Name="txtLiveLog" Grid.Row="1" Height="140" IsReadOnly="True" AcceptsReturn="True"
                     VerticalScrollBarVisibility="Auto" TextWrapping="Wrap" Background="#FAFAFA"/>
        </Grid>
    </Expander>


    <Expander Grid.Row="3" Header="Help" Margin="0,10,0,0">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Height="220">
            <StackPanel>
                <TextBlock Text="About Encryption" FontWeight="Bold" Margin="0,0,0,6"/>
                <TextBlock TextWrapping="Wrap" Margin="0,0,0,12">CFEM - Cloud File Encryption Manager encrypts files locally before any cloud synchronization occurs. Encryption uses modern cryptography provided by the Windows/.NET security libraries. A user-supplied password is used to derive an encryption key, and encrypted files are written as new output files. Original files are never uploaded to cloud providers-only the encrypted output is copied to services such as OneDrive, Dropbox, or Google Drive.

Important: If the encryption password is lost, encrypted files cannot be recovered.</TextBlock>

                <TextBlock Text="FAQ" FontWeight="Bold" Margin="0,0,0,6"/>
                <TextBlock TextWrapping="Wrap">
                    <Run FontWeight="Bold" Text="* How are files encrypted?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  Files are encrypted locally using modern symmetric encryption via the Windows/.NET cryptography stack, before any cloud sync occurs."/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run FontWeight="Bold" Text="* Is my password stored anywhere?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  No. The password is used only to derive keys during encryption/decryption and is not stored in plaintext."/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run FontWeight="Bold" Text="* Are my original files modified or deleted?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  No. Encrypted files are written as new output files (for example, with a .encrypted extension)."/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run FontWeight="Bold" Text="* What happens if I lose my password?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  There is no recovery mechanism. Without the correct password, encrypted files cannot be decrypted."/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run FontWeight="Bold" Text="* Does this rely on OneDrive/Dropbox/Google Drive encryption?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  No. Encryption is performed locally first; cloud providers only ever receive encrypted data."/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run FontWeight="Bold" Text="* Why not encrypt directly inside the OneDrive folder?"/>
                    <LineBreak/>
                    <LineBreak/>
                    <Run Text="  Encrypting inside cloud-synced folders can cause partial uploads and sync conflicts. This tool stages encrypted output locally, then syncs the completed encrypted files."/>
                    <LineBreak/>
                    <LineBreak/>
                </TextBlock>
            </StackPanel>
        </ScrollViewer>
    </Expander>
</Grid>
        </Border>
        
        <!-- Status Bar -->
        <Border Grid.Row="4" Background="#34495E" CornerRadius="3" Padding="10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                
                <TextBlock Name="txtStatus" Grid.Column="0" Text="Ready to encrypt your files" 
                          Foreground="White" VerticalAlignment="Center"/>
                <TextBlock Name="txtTimestamp" Grid.Column="1" Foreground="#ECF0F1" 
                          VerticalAlignment="Center"/>
            </Grid>
        </Border>
    </Grid>
</Window>
"@

#endregion

#region Core Encryption Functions

function Get-PBKDF2Key {
    param(
        [string]$Password,
        [byte[]]$Salt,
        [int]$Iterations = 250000,
        [int]$KeyLength = 32
    )
    
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $Password, 
        $Salt, 
        $Iterations,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    
    return $pbkdf2.GetBytes($KeyLength)
}

function Encrypt-FileAES {
    param(
        [string]$FilePath,
        [string]$Password,
        [int]$Iterations = 250000,
        [string]$OutputExtension = ".encrypted",
        [string]$OutputRoot = $null,
        [string]$SourceRoot = $null
    )
    
    try {
        Write-Log "Encrypting file: $FilePath"
        
        # Read file data
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Generate random salt and IV
        $salt = New-Object byte[] 32
        $iv = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($salt)
        $rng.GetBytes($iv)
        
        # Derive encryption key from password
        $key = Get-PBKDF2Key -Password $Password -Salt $salt -Iterations $Iterations -KeyLength 32
        
        # Create AES encryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Encrypt data
        $encryptor = $aes.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)
        
        # Generate HMAC for integrity verification
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $key
        $dataToAuth = $salt + $iv + $encryptedData
        $hmacValue = $hmac.ComputeHash($dataToAuth)
        
        # Construct output file: [Salt 32][IV 16][HMAC 32][Encrypted Data]
        # Determine output path
        if ($OutputRoot) {
            if (-not $SourceRoot) { $SourceRoot = Split-Path -Path $FilePath -Parent }
            $rel = Get-RelativePath -BasePath $SourceRoot -TargetPath $FilePath
            $relDir = Split-Path -Path $rel -Parent
            $outDir = if ($relDir -and $relDir -ne ".") { Join-Path $OutputRoot $relDir } else { $OutputRoot }
            Ensure-Directory -Path $outDir
            $leaf = Split-Path -Path $FilePath -Leaf
            $outputPath = Join-Path $outDir ($leaf + $OutputExtension)
        } else {
            $outputPath = "$FilePath$OutputExtension"
        }$outputData = $salt + $iv + $hmacValue + $encryptedData
        
        [System.IO.File]::WriteAllBytes($outputPath, $outputData)
        
        # Preserve timestamps if configured
        if ($script:settings.PreserveTimestamps) {
            $originalFile = Get-Item $FilePath
            $encryptedFile = Get-Item $outputPath
            $encryptedFile.CreationTime = $originalFile.CreationTime
            $encryptedFile.LastWriteTime = $originalFile.LastWriteTime
            $encryptedFile.LastAccessTime = $originalFile.LastAccessTime
        }
        
        Write-Log "Successfully encrypted: $FilePath -> $outputPath" -Level Success
        
        return @{
            Success = $true
            OutputPath = $outputPath
            OriginalSize = $fileBytes.Length
            EncryptedSize = $outputData.Length
        }
    }
    catch {
        Write-Log "Failed to encrypt $FilePath : $_" -Level Error
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($aes) { $aes.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
        if ($hmac) { $hmac.Dispose() }
        if ($rng) { $rng.Dispose() }
        
        # Clear sensitive data from memory
        if ($key) { [Array]::Clear($key, 0, $key.Length) }
        if ($fileBytes) { [Array]::Clear($fileBytes, 0, $fileBytes.Length) }
    }
}

function Decrypt-FileAES {
    param(
        [string]$FilePath,
        [string]$Password,
        [int]$Iterations = 250000,
        [string]$InputExtension = ".encrypted"
    )
    
    try {
        Write-Log "Decrypting file: $FilePath"
        
        # Read encrypted file
        $encryptedData = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Verify minimum file size (Salt 32 + IV 16 + HMAC 32 = 80 bytes minimum)
        if ($encryptedData.Length -lt 80) {
            throw "File is too small to be a valid encrypted file"
        }
        
        # Extract components
        $salt = $encryptedData[0..31]
        $iv = $encryptedData[32..47]
        $storedHmac = $encryptedData[48..79]
        $cipherText = $encryptedData[80..($encryptedData.Length - 1)]
        
        # Derive decryption key from password
        $key = Get-PBKDF2Key -Password $Password -Salt $salt -Iterations $Iterations -KeyLength 32
        
        # Verify HMAC (integrity check)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = $key
        $dataToAuth = $salt + $iv + $cipherText
        $calculatedHmac = $hmac.ComputeHash($dataToAuth)
        
        # Compare HMACs
        $hmacMatch = $true
        for ($i = 0; $i -lt 32; $i++) {
            if ($storedHmac[$i] -ne $calculatedHmac[$i]) {
                $hmacMatch = $false
                break
            }
        }
        
        if (-not $hmacMatch) {
            throw "HMAC verification failed - file may be corrupted or password is incorrect"
        }
        
        # Create AES decryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Decrypt data
        $decryptor = $aes.CreateDecryptor()
        $decryptedData = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
        
        # Determine output path (remove encryption extension)
        $outputPath = $FilePath
        if ($FilePath.EndsWith($InputExtension)) {
            $outputPath = $FilePath.Substring(0, $FilePath.Length - $InputExtension.Length)
        }
        else {
            $outputPath = "$FilePath.decrypted"
        }
        
        [System.IO.File]::WriteAllBytes($outputPath, $decryptedData)
        
        # Preserve timestamps if configured
        if ($script:settings.PreserveTimestamps) {
            $encryptedFile = Get-Item $FilePath
            $decryptedFile = Get-Item $outputPath
            $decryptedFile.CreationTime = $encryptedFile.CreationTime
            $decryptedFile.LastWriteTime = $encryptedFile.LastWriteTime
            $decryptedFile.LastAccessTime = $encryptedFile.LastAccessTime
        }
        
        Write-Log "Successfully decrypted: $FilePath -> $outputPath" -Level Success
        
        return @{
            Success = $true
            OutputPath = $outputPath
            DecryptedSize = $decryptedData.Length
            EncryptedSize = $encryptedData.Length
        }
    }
    catch {
        Write-Log "Failed to decrypt $FilePath : $_" -Level Error
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($aes) { $aes.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
        if ($hmac) { $hmac.Dispose() }
        
        # Clear sensitive data from memory
        if ($key) { [Array]::Clear($key, 0, $key.Length) }
        if ($decryptedData) { [Array]::Clear($decryptedData, 0, $decryptedData.Length) }
        if ($cipherText) { [Array]::Clear($cipherText, 0, $cipherText.Length) }
    }
}

function Remove-FileSecurely {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Log "File not found for secure deletion: $FilePath" -Level Warning
            return
        }
        
        $file = Get-Item $FilePath
        $fileSize = $file.Length
        
        # DOD 5220.22-M standard: 7-pass overwrite
        $patterns = @(
            [byte]0x00,  # Pass 1: All zeros
            [byte]0xFF,  # Pass 2: All ones
            [byte]0x00,  # Pass 3: All zeros
            [byte]0xFF,  # Pass 4: All ones
            [byte]0x00,  # Pass 5: All zeros
            [byte]0xFF,  # Pass 6: All ones
            $null        # Pass 7: Random data
        )
        
        Write-Log "Securely deleting file: $FilePath (7-pass overwrite)"
        
        foreach ($pass in 0..6) {
            $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
            
            try {
                if ($pass -eq 6) {
                    # Random data for final pass
                    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
                    $buffer = New-Object byte[] 4096
                    
                    $bytesRemaining = $fileSize
                    while ($bytesRemaining -gt 0) {
                        $bytesToWrite = [Math]::Min(4096, $bytesRemaining)
                        $rng.GetBytes($buffer)
                        $stream.Write($buffer, 0, $bytesToWrite)
                        $bytesRemaining -= $bytesToWrite
                    }
                    $rng.Dispose()
                }
                else {
                    # Pattern overwrite
                    $buffer = New-Object byte[] 4096
                    for ($i = 0; $i -lt $buffer.Length; $i++) {
                        $buffer[$i] = $patterns[$pass]
                    }
                    
                    $bytesRemaining = $fileSize
                    while ($bytesRemaining -gt 0) {
                        $bytesToWrite = [Math]::Min(4096, $bytesRemaining)
                        $stream.Write($buffer, 0, $bytesToWrite)
                        $bytesRemaining -= $bytesToWrite
                    }
                }
                
                $stream.Flush()
            }
            finally {
                $stream.Close()
                $stream.Dispose()
            }
        }
        
        # Delete the file
        Remove-Item $FilePath -Force
        
        Write-Log "Securely deleted: $FilePath" -Level Success
    }
    catch {
        Write-Log "Failed to securely delete $FilePath : $_" -Level Error
        throw
    }
}

#endregion

#region Helper Functions

function Initialize-Logging {
    # File-based logging + live UI log
    $script:LogDir = Join-Path $env:LOCALAPPDATA "CloudFileEncryptionManager\Logs"
    Ensure-Directory -Path $script:LogDir
    $script:LogFilePath = Join-Path $script:LogDir ("CloudFileEncryptionManager_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    # Touch the file so the "Open Logs" button always has something to show
    "" | Out-File -FilePath $script:LogFilePath -Encoding UTF8 -Force
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"

    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        default   { "White" }
    }

    # Console (if any)
    Write-Host $line -ForegroundColor $color

    # File logging (best-effort)
    try {
        if (-not $script:LogFilePath) {
            $fallbackDir = Join-Path $env:TEMP "CloudFileEncryptionManager"
            Ensure-Directory -Path $fallbackDir
            $script:LogFilePath = Join-Path $fallbackDir "CloudFileEncryptionManager.log"
        }
        $line | Out-File -FilePath $script:LogFilePath -Encoding UTF8 -Append
    } catch {
        # Swallow logging failures
    }

    # Live UI log (best-effort)
    try {
        if ($script:txtLiveLog) {
            $script:txtLiveLog.AppendText($line + [Environment]::NewLine)
            $script:txtLiveLog.ScrollToEnd()
        }
    } catch {
        # Swallow UI logging failures
    }
}


function Get-DefaultEncryptedOutputRoot {
    # Local working output (NOT inside cloud folders to avoid sync loops)
    $root = Join-Path $env:LOCALAPPDATA "CloudFileEncryptionManager\EncryptedOutput"
    if (-not (Test-Path $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }
    return $root
}

function New-EncryptionJobOutputRoot {
    $base = Get-DefaultEncryptedOutputRoot
    $job = "Job_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
    $path = Join-Path $base $job
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory)] [string] $BasePath,
        [Parameter(Mandatory)] [string] $TargetPath
    )

    try {
        $base = (Resolve-Path -Path $BasePath).Path
        $target = (Resolve-Path -Path $TargetPath).Path

        if (-not $base.EndsWith('\')) { $base = $base + '\' }

        $baseUri = New-Object System.Uri($base)
        $targetUri = New-Object System.Uri($target)
        $rel = $baseUri.MakeRelativeUri($targetUri).ToString()
        $rel = [System.Uri]::UnescapeDataString($rel)
        return ($rel -replace '/', '\')
    } catch {
        # Fallback: just return leaf
        return (Split-Path $TargetPath -Leaf)
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Normalize-CloudPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }

    # Trim whitespace and surrounding quotes
    $p = $Path.Trim()
    $p = $p.Trim('"').Trim("'")

    # Expand environment variables (e.g. %OneDrive%)
    $p = [Environment]::ExpandEnvironmentVariables($p)

    return $p
}

function Get-CloudSubfolder {
    # Read from UI if present; fallback to settings; default to "Encrypted"
    $sub = ""
    try {
        if ($script:txtCloudSubfolder) { $sub = $script:txtCloudSubfolder.Text }
    } catch { }

    if ([string]::IsNullOrWhiteSpace($sub)) {
        try {
            if ($script:settings -and $script:settings.CloudSubfolder) { $sub = $script:settings.CloudSubfolder }
        } catch { }
    }

    $sub = Normalize-CloudPath -Path $sub
    if ([string]::IsNullOrWhiteSpace($sub)) { $sub = "Encrypted" }

    # Prevent rooted paths; only allow a relative subfolder under provider root
    $sub = $sub.TrimStart("\").TrimStart("/")
    return $sub
}

function Get-QueuePath {
    $dir = Join-Path $env:APPDATA "CloudFileEncryptionManager"
    Ensure-Directory -Path $dir
    return (Join-Path $dir "sync-queue.json")
}

function Load-SyncQueue {
    $path = Get-QueuePath
    if (-not (Test-Path $path)) { return @() }
    $raw = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    try { return ($raw | ConvertFrom-Json) } catch { return @() }
}

function Save-SyncQueue {
    param([Parameter(Mandatory)]$Queue)
    $path = Get-QueuePath
    ($Queue | ConvertTo-Json -Depth 8) | Set-Content -Path $path -Encoding UTF8
}

function Enqueue-SyncItem {
    param(
        [Parameter(Mandatory)] [string] $EncryptedPath,
        [Parameter(Mandatory)] [string] $Provider,
        [Parameter(Mandatory)] [string] $DestinationRoot
    )

    $queue = @(Load-SyncQueue)

    $queue += [pscustomobject]@{
        id             = [guid]::NewGuid().ToString()
        encryptedPath  = $EncryptedPath
        provider       = $Provider
        destination    = $DestinationRoot
        status         = "pending"
        addedUtc       = (Get-Date).ToUniversalTime().ToString("o")
        lastAttemptUtc = $null
        attemptCount   = 0
        lastError      = $null
    }

    Save-SyncQueue -Queue $queue

    # Return a small summary for UI feedback
    $copied = @($queue | Where-Object { $_.status -eq "copied" }).Count
    $failed = @($queue | Where-Object { $_.status -eq "failed" }).Count
    $pending = @($queue | Where-Object { $_.status -ne "copied" }).Count

    return [pscustomobject]@{
        Copied  = $copied
        Failed  = $failed
        Pending = $pending
    }
}

function Process-SyncQueue {
    param(
        [int] $MaxRetries = 5
    )

    $queue = @(Load-SyncQueue)
    if (-not $queue -or $queue.Count -eq 0) {
        Write-Log "Cloud sync: nothing queued." -Level Info
        return [pscustomobject]@{ Copied = 0; Failed = 0; Pending = 0 }
    }

    foreach ($item in $queue) {
        if ($item.status -eq "copied") { continue }
        if ([int]$item.attemptCount -ge $MaxRetries) { continue }

        $item.lastAttemptUtc = (Get-Date).ToUniversalTime().ToString("o")
        $item.attemptCount   = [int]$item.attemptCount + 1

        try {
            $src = $item.encryptedPath
            $destRoot = $item.destination

            if (-not (Test-Path $src)) {
                throw "Source missing: $src"
            }

            Ensure-Directory -Path $destRoot

            $srcItem = Get-Item -Path $src -ErrorAction Stop
            $destPath = $null

            if ($srcItem.PSIsContainer) {
                $leaf = Split-Path $src -Leaf
                $destPath = Join-Path $destRoot $leaf
                Copy-Item -Path $src -Destination $destPath -Recurse -Force
            } else {
                $destPath = Join-Path $destRoot (Split-Path $src -Leaf)
                Copy-Item -Path $src -Destination $destRoot -Force
            }

            # Post-copy verification
            if (-not (Test-Path $destPath)) {
                throw "Post-copy verify failed: destination missing: $destPath"
            }

            if (-not $srcItem.PSIsContainer) {
                $srcLen = (Get-Item -Path $src -ErrorAction Stop).Length
                $dstLen = (Get-Item -Path $destPath -ErrorAction Stop).Length
                if ($srcLen -ne $dstLen) {
                    throw "Post-copy verify failed: size mismatch (src=$srcLen bytes, dst=$dstLen bytes)"
                }
                Write-Log ("Cloud sync OK (verified): {0} -> {1} ({2})" -f $src, $destPath, (Format-FileSize -Size $dstLen)) -Level Success
            } else {
                $count = @(Get-ChildItem -Path $destPath -Recurse -Force -ErrorAction SilentlyContinue).Count
                Write-Log ("Cloud sync OK (verified): {0} -> {1} ({2} items)" -f $src, $destPath, $count) -Level Success
            }
        }
        catch {
            $item.status = "failed"
            $item.lastError = $_.Exception.Message
            Write-Log "Cloud sync FAILED: $($item.encryptedPath) -> $($item.destination) : $($item.lastError)" -Level Error
        }
    }

    Save-SyncQueue -Queue $queue

    # Return a small summary for UI feedback
    $copied = @($queue | Where-Object { $_.status -eq "copied" }).Count
    $failed = @($queue | Where-Object { $_.status -eq "failed" }).Count
    $pending = @($queue | Where-Object { $_.status -ne "copied" }).Count

    return [pscustomobject]@{
        Copied  = $copied
        Failed  = $failed
        Pending = $pending
    }
}


function Format-FileSize {
    param([long]$Size)
    
    if ($Size -gt 1GB) {
        return "{0:N2} GB" -f ($Size / 1GB)
    }
    elseif ($Size -gt 1MB) {
        return "{0:N2} MB" -f ($Size / 1MB)
    }
    elseif ($Size -gt 1KB) {
        return "{0:N2} KB" -f ($Size / 1KB)
    }
    else {
        return "$Size bytes"
    }
}

function Update-Status {
    param(
        [string]$Message,
        [string]$Detail = ""
    )
    
    $script:txtStatus.Text = $Message
    $script:txtProgressStatus.Text = $Message
    $script:txtProgressDetail.Text = $Detail
    $script:txtTimestamp.Text = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $script:window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background)
}

function Update-Progress {
    param(
        [int]$Value,
        [int]$Maximum = 100
    )
    
    $script:progressBar.Maximum = $Maximum
    $script:progressBar.Value = $Value
    
    $script:window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background)
}

function Get-PasswordFromUI {
    $password = $script:txtPassword.Password
    
    if ([string]::IsNullOrWhiteSpace($password)) {
        if ($script:sessionPassword) {
            return $script:sessionPassword
        }
        else {
            throw "Please enter an encryption password"
        }
    }
    
    if ($script:chkRememberPassword.IsChecked) {
        $script:sessionPassword = $password
    }
    
    return $password
}

function Test-EncryptedFile {
    param([string]$FilePath)
    
    $extension = $script:settings.EncryptedExtension
    return $FilePath.EndsWith($extension)
}

function Add-FileToList {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [string]$Status = "[PLAIN]",
        [string]$RootPath = $null
    )

    $file = Get-Item $FilePath
    $isEncrypted = Test-EncryptedFile -FilePath $FilePath

    if (-not $RootPath) {
        $RootPath = Split-Path -Path $FilePath -Parent
    }

    $item = New-Object PSObject -Property @{
        Status   = if ($isEncrypted) { "[ENC]" } else { "[PLAIN]" }
        Path     = $FilePath
        RootPath = $RootPath
        Size     = Format-FileSize -Size $file.Length
        Type     = if ($isEncrypted) { "Encrypted" } else { "Plain Text" }
    }

    $script:lstFiles.Items.Add($item) | Out-Null
}

function Detect-CloudFolders {
    # OneDrive (recommended detection order: env vars -> registry -> fallback)
    $onedrive = $env:OneDrive
    if (-not $onedrive) { $onedrive = $env:OneDriveConsumer }
    if (-not $onedrive) { $onedrive = $env:OneDriveCommercial }

    if (-not $onedrive) {
        try {
            $reg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\OneDrive" -ErrorAction Stop
            if ($reg.UserFolder) { $onedrive = $reg.UserFolder }
        } catch { }
    }

    if (-not $onedrive) {
        $onedrive = Join-Path $env:USERPROFILE "OneDrive"
    }

    if ($onedrive -and (Test-Path $onedrive)) {
        $script:txtOneDrivePath.Text = $onedrive
    }

    # Google Drive (multiple possible locations)
    $googleDriveLocations = @(
        (Join-Path $env:USERPROFILE "Google Drive"),
        "G:\My Drive",
        "G:\Shared drives"
    )

    foreach ($location in $googleDriveLocations) {
        if (Test-Path $location) {
            $script:txtGoogleDrivePath.Text = $location
            break
        }
    }

    # Dropbox (best-effort default)
    $dropbox = Join-Path $env:USERPROFILE "Dropbox"
    if (Test-Path $dropbox) {
        $script:txtDropboxPath.Text = $dropbox
    }
}

#endregion

#region UI Event Handlers

function Initialize-UI {
    # Detect cloud storage folders
    Detect-CloudFolders
    
    # Set default settings
    $script:settings = @{
        Algorithm = "AES-256"
        Iterations = 250000
        EncryptedExtension = ".encrypted"
        DeleteOriginal = $false
        SecureDelete = $true
        DeleteEncrypted = $false
        PreserveTimestamps = $true
        CloudSubfolder = "Encrypted"
    }
    
    $script:sessionPassword = $null
    $script:monitoringActive = $false
    
    Update-Status -Message "Ready to encrypt your files"

    # Default: enable post-encrypt cloud sync (uses selected providers)
    if ($script:chkSyncToCloud) { $script:chkSyncToCloud.IsChecked = $true }
    if ($script:txtCloudSubfolder) { $script:txtCloudSubfolder.Text = $script:settings.CloudSubfolder }
}

function Show-PasswordToggle {
    # This would require a TextBox instead of PasswordBox
    # For security, we'll show a message instead
    [System.Windows.MessageBox]::Show(
        "For security reasons, passwords are hidden.`n`nPassword length: $($script:txtPassword.Password.Length) characters",
        "Password Information",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information
    )
}

function Select-FilesForEncryption {
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "All Files (*.*)|*.*"
    $openDialog.Title = "Select Files to Encrypt/Decrypt"
    $openDialog.Multiselect = $true
    
    if ($openDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        foreach ($file in $openDialog.FileNames) {
            Add-FileToList -FilePath $file -RootPath (Split-Path -Path $file -Parent)
        }
        
        $script:txtSelectionCount.Text = "$($script:lstFiles.Items.Count) items selected"
        Update-Status -Message "Selected $($script:lstFiles.Items.Count) file(s)"
    }
}

function Select-FolderForEncryption {
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select Folder to Encrypt/Decrypt"
    $folderDialog.ShowNewFolderButton = $false
    
    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $files = Get-ChildItem -Path $folderDialog.SelectedPath -File -Recurse
        
        foreach ($file in $files) {
            Add-FileToList -FilePath $file.FullName -RootPath $folderDialog.SelectedPath
        }
        
        $script:txtSelectionCount.Text = "$($script:lstFiles.Items.Count) items selected"
        Update-Status -Message "Selected $($script:lstFiles.Items.Count) file(s) from folder"
    }
}

function Clear-FileSelection {
    $script:lstFiles.Items.Clear()
    $script:txtSelectionCount.Text = "0 items selected"
    Update-Status -Message "File selection cleared"
}

function Start-EncryptionProcess {
    if ($script:lstFiles.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "Please select files to encrypt.",
            "No Files Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }
    
    try {
        $password = Get-PasswordFromUI
        
        if ($password.Length -lt 8) {
            $result = [System.Windows.MessageBox]::Show(
                "Your password is less than 8 characters. This is not recommended for security.`n`nContinue anyway?",
                "Weak Password",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Warning
            )
            
            if ($result -eq [System.Windows.MessageBoxResult]::No) {
                return
            }
        }
        
        $iterations = [int]$script:cmbIterations.SelectedItem.Tag
        $extension = $script:txtEncryptedExtension.Text
        
        # Create a dedicated landing folder for this encryption run
        $jobOutputRoot = New-EncryptionJobOutputRoot
        Write-Log "Encryption landing folder: $jobOutputRoot"
        
        $totalFiles = $script:lstFiles.Items.Count
        $currentFile = 0
        $successCount = 0
        $failCount = 0
        
        Update-Status -Message "Encrypting files..." -Detail "0 / $totalFiles"
        
        foreach ($item in $script:lstFiles.Items) {
            $currentFile++
            Update-Progress -Value $currentFile -Maximum $totalFiles
            Update-Status -Message "Encrypting files..." -Detail "$currentFile / $totalFiles"
            
            $filePath = $item.Path
            
            # Skip if already encrypted
            if (Test-EncryptedFile -FilePath $filePath) {
                Write-Log "Skipping already encrypted file: $filePath" -Level Warning
                continue
            }
            
            $result = Encrypt-FileAES -FilePath $filePath -Password $password -Iterations $iterations -OutputExtension $extension -OutputRoot $jobOutputRoot -SourceRoot $item.RootPath
            
            if ($result.Success) {
                $successCount++
                
                # Queue newly encrypted output for cloud sync (only if enabled)
                if ($script:chkSyncToCloud.IsChecked) {
                    $cloudSubfolder = Get-CloudSubfolder
                    
                    if ($script:chkOneDrive.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtOneDrivePath.Text)) {
                        $root = Normalize-CloudPath -Path $script:txtOneDrivePath.Text
                        $dest = Join-Path $root $cloudSubfolder
                        Enqueue-SyncItem -EncryptedPath $result.OutputPath -Provider "OneDrive" -DestinationRoot $dest
                    }
                    if ($script:chkGoogleDrive.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtGoogleDrivePath.Text)) {
                        $root = Normalize-CloudPath -Path $script:txtGoogleDrivePath.Text
                        $dest = Join-Path $root $cloudSubfolder
                        Enqueue-SyncItem -EncryptedPath $result.OutputPath -Provider "GoogleDrive" -DestinationRoot $dest
                    }
                    if ($script:chkDropbox.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtDropboxPath.Text)) {
                        $root = Normalize-CloudPath -Path $script:txtDropboxPath.Text
                        $dest = Join-Path $root $cloudSubfolder
                        Enqueue-SyncItem -EncryptedPath $result.OutputPath -Provider "Dropbox" -DestinationRoot $dest
                    }
                }
                
                # Delete original if configured
                if ($script:chkDeleteOriginal.IsChecked) {
                    if ($script:chkSecureDelete.IsChecked) {
                        Remove-FileSecurely -FilePath $filePath
                    }
                    else {
                        Remove-Item $filePath -Force
                    }
                }
            }
            else {
                $failCount++
            }
        }
        
        Update-Progress -Value 0
        
        if ($script:chkSyncToCloud.IsChecked) {
            # Ensure provider destination folders exist even if nothing new was queued (makes it visible in OneDrive etc.)
            $cloudSubfolder = Get-CloudSubfolder
            if ($script:chkOneDrive.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtOneDrivePath.Text)) {
                $root = Normalize-CloudPath -Path $script:txtOneDrivePath.Text
                Ensure-Directory -Path (Join-Path $root $cloudSubfolder)
            }
            if ($script:chkGoogleDrive.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtGoogleDrivePath.Text)) {
                $root = Normalize-CloudPath -Path $script:txtGoogleDrivePath.Text
                Ensure-Directory -Path (Join-Path $root $cloudSubfolder)
            }
            if ($script:chkDropbox.IsChecked -and -not [string]::IsNullOrWhiteSpace($script:txtDropboxPath.Text)) {
                $root = Normalize-CloudPath -Path $script:txtDropboxPath.Text
                Ensure-Directory -Path (Join-Path $root $cloudSubfolder)
            }

            Update-Status -Message "Syncing newly encrypted outputs to cloud folders..." -Detail ""
            $syncSummary = Process-SyncQueue
            $queuePath = (Get-QueuePath)
            $msg = "Cloud Sync Results:`n`nCopied: $($syncSummary.Copied)`nFailed: $($syncSummary.Failed)`nPending: $($syncSummary.Pending)"
            if ($syncSummary.Failed -gt 0) { $msg += "`n`nQueue file:`n$queuePath" }
            $icon = if ($syncSummary.Failed -gt 0) { [System.Windows.MessageBoxImage]::Warning } else { [System.Windows.MessageBoxImage]::Information }
            [System.Windows.MessageBox]::Show(
                $msg,
                "Cloud Sync",
                [System.Windows.MessageBoxButton]::OK,
                $icon
            ) | Out-Null
        }
        Update-Status -Message "Encryption complete: $successCount succeeded, $failCount failed"
        
        [System.Windows.MessageBox]::Show(
            "Encryption completed!`n`nSuccessful: $successCount`nFailed: $failCount",
            "Encryption Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information
        )
        
        Clear-FileSelection
    }
    catch {
        Update-Status -Message "Encryption failed: $_"
        [System.Windows.MessageBox]::Show(
            "Encryption failed: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

function Start-DecryptionProcess {
    if ($script:lstFiles.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "Please select files to decrypt.",
            "No Files Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }
    
    try {
        $password = Get-PasswordFromUI
        $iterations = [int]$script:cmbIterations.SelectedItem.Tag
        $extension = $script:txtEncryptedExtension.Text
        
        $totalFiles = $script:lstFiles.Items.Count
        $currentFile = 0
        $successCount = 0
        $failCount = 0
        
        Update-Status -Message "Decrypting files..." -Detail "0 / $totalFiles"
        
        foreach ($item in $script:lstFiles.Items) {
            $currentFile++
            Update-Progress -Value $currentFile -Maximum $totalFiles
            Update-Status -Message "Decrypting files..." -Detail "$currentFile / $totalFiles"
            
            $filePath = $item.Path
            
            # Skip if not encrypted
            if (-not (Test-EncryptedFile -FilePath $filePath)) {
                Write-Log "Skipping non-encrypted file: $filePath" -Level Warning
                continue
            }
            
            $result = Decrypt-FileAES -FilePath $filePath -Password $password -Iterations $iterations -InputExtension $extension
            
            if ($result.Success) {
                $successCount++
                
                # Delete encrypted if configured
                if ($script:chkDeleteEncrypted.IsChecked) {
                    if ($script:chkSecureDelete.IsChecked) {
                        Remove-FileSecurely -FilePath $filePath
                    }
                    else {
                        Remove-Item $filePath -Force
                    }
                }
            }
            else {
                $failCount++
                
                # Common error: wrong password
                if ($result.Error -like "*HMAC verification failed*") {
                    [System.Windows.MessageBox]::Show(
                        "Decryption failed: Wrong password or corrupted file.`n`nFile: $filePath",
                        "Decryption Error",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Error
                    )
                    break
                }
            }
        }
        
        Update-Progress -Value 0
        Update-Status -Message "Decryption complete: $successCount succeeded, $failCount failed"
        
        [System.Windows.MessageBox]::Show(
            "Decryption completed!`n`nSuccessful: $successCount`nFailed: $failCount",
            "Decryption Complete",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information
        )
        
        Clear-FileSelection
    }
    catch {
        Update-Status -Message "Decryption failed: $_"
        [System.Windows.MessageBox]::Show(
            "Decryption failed: $_",
            "Error",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        )
    }
}

function Start-SecureDeleteProcess {
    if ($script:lstFiles.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "Please select files to delete.",
            "No Files Selected",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return
    }
    
    $result = [System.Windows.MessageBox]::Show(
        "CRITICAL WARNING`n`nThis will permanently delete $($script:lstFiles.Items.Count) file(s) using 7-pass secure deletion.`n`nDeleted files CANNOT be recovered!`n`nAre you absolutely sure?",
        "Confirm Secure Delete",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    
    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
        try {
            $totalFiles = $script:lstFiles.Items.Count
            $currentFile = 0
            
            Update-Status -Message "Securely deleting files..." -Detail "0 / $totalFiles"
            
            foreach ($item in $script:lstFiles.Items) {
                $currentFile++
                Update-Progress -Value $currentFile -Maximum $totalFiles
                Update-Status -Message "Securely deleting files..." -Detail "$currentFile / $totalFiles"
                
                Remove-FileSecurely -FilePath $item.Path
            }
            
            Update-Progress -Value 0
            Update-Status -Message "Secure deletion complete"
            
            [System.Windows.MessageBox]::Show(
                "Secure deletion completed!`n`n$totalFiles file(s) permanently deleted.",
                "Deletion Complete",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            )
            
            Clear-FileSelection
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Secure deletion failed: $_",
                "Error",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            )
        }
    }
}

# Auto-Encrypt Functions
function Select-MonitorFolder {
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select Folder to Monitor for Auto-Encryption"
    $folderDialog.ShowNewFolderButton = $false
    
    if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:txtMonitorFolder.Text = $folderDialog.SelectedPath
        
        if ($script:chkAutoEncryptEnabled.IsChecked -and $script:txtPassword.Password.Length -gt 0) {
            $script:btnStartMonitoring.IsEnabled = $true
        }
    }
}

function Start-FileMonitoring {
    try {
        if ([string]::IsNullOrWhiteSpace($script:txtMonitorFolder.Text)) {
            [System.Windows.MessageBox]::Show("Please select a folder to monitor.", "No Folder Selected", 
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        
        $password = Get-PasswordFromUI
        
        # Create FileSystemWatcher
        $script:fileWatcher = New-Object System.IO.FileSystemWatcher
        $script:fileWatcher.Path = $script:txtMonitorFolder.Text
        $script:fileWatcher.Filter = "*.*"
        $script:fileWatcher.IncludeSubdirectories = $true
        $script:fileWatcher.EnableRaisingEvents = $true
        
        # Get filter settings
        $includeExts = $script:txtIncludeExtensions.Text.Split(',') | ForEach-Object { $_.Trim() }
        $excludeExts = $script:txtExcludeExtensions.Text.Split(',') | ForEach-Object { $_.Trim() }
        
        $action = {
            $path = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            
            # Skip if already encrypted
            if ($path.EndsWith($script:settings.EncryptedExtension)) {
                return
            }
            
            # Apply filters
            $ext = [System.IO.Path]::GetExtension($path).ToLower()
            
            if ($includeExts -and $includeExts.Count -gt 0 -and $includeExts[0] -ne "") {
                if ($ext -notin $includeExts) {
                    return
                }
            }
            
            if ($excludeExts -and $excludeExts.Count -gt 0 -and $excludeExts[0] -ne "") {
                if ($ext -in $excludeExts) {
                    return
                }
            }
            
            # Wait a bit to ensure file is fully written
            Start-Sleep -Milliseconds 500
            
            # Encrypt the file
            $timestamp = Get-Date -Format "HH:mm:ss"
            $logMessage = "[$timestamp] NEW FILE: $path"
            
            $script:window.Dispatcher.Invoke([Action]{
                $script:txtAutoEncryptLog.AppendText("$logMessage`n")
                $script:txtAutoEncryptLog.ScrollToEnd()
            })
            
            try {
                $result = Encrypt-FileAES -FilePath $path -Password $script:sessionPassword `
                    -Iterations $script:settings.Iterations -OutputExtension $script:settings.EncryptedExtension
                
                if ($result.Success) {
                    $logMessage = "[$timestamp] [OK] ENCRYPTED: $path"
                    
                    # Delete original if configured
                    if ($script:settings.DeleteOriginal) {
                        if ($script:settings.SecureDelete) {
                            Remove-FileSecurely -FilePath $path
                        }
                        else {
                            Remove-Item $path -Force
                        }
                        $logMessage += " (original deleted)"
                    }
                }
                else {
                    $logMessage = "[$timestamp] [FAIL] ERROR: $path - $($result.Error)"
                }
            }
            catch {
                $logMessage = "[$timestamp] [FAIL] ERROR: $path - $_"
            }
            
            $script:window.Dispatcher.Invoke([Action]{
                $script:txtAutoEncryptLog.AppendText("$logMessage`n")
                $script:txtAutoEncryptLog.ScrollToEnd()
            })
        }
        
        $script:fileWatcherEvent = Register-ObjectEvent $script:fileWatcher "Created" -Action $action
        
        $script:monitoringActive = $true
        $script:btnStartMonitoring.IsEnabled = $false
        $script:btnStopMonitoring.IsEnabled = $true
        
        $timestamp = Get-Date -Format "HH:mm:ss"
        $script:txtAutoEncryptLog.AppendText("[$timestamp] [START] MONITORING STARTED: $($script:txtMonitorFolder.Text)`n")
        $script:txtAutoEncryptLog.ScrollToEnd()
        
        Update-Status -Message "Auto-encryption monitoring active"
        
        Write-Log "Auto-encryption monitoring started for: $($script:txtMonitorFolder.Text)" -Level Success
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to start monitoring: $_", "Error", 
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Stop-FileMonitoring {
    try {
        if ($script:fileWatcher) {
            $script:fileWatcher.EnableRaisingEvents = $false
            $script:fileWatcher.Dispose()
            $script:fileWatcher = $null
        }
        
        if ($script:fileWatcherEvent) {
            Unregister-Event $script:fileWatcherEvent.Name
            $script:fileWatcherEvent = $null
        }
        
        $script:monitoringActive = $false
        $script:btnStartMonitoring.IsEnabled = $true
        $script:btnStopMonitoring.IsEnabled = $false
        
        $timestamp = Get-Date -Format "HH:mm:ss"
        $script:txtAutoEncryptLog.AppendText("[$timestamp] [STOP] MONITORING STOPPED`n")
        $script:txtAutoEncryptLog.ScrollToEnd()
        
        Update-Status -Message "Auto-encryption monitoring stopped"
        
        Write-Log "Auto-encryption monitoring stopped" -Level Success
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to stop monitoring: $_", "Error", 
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Clear-MonitorLog {
    $script:txtAutoEncryptLog.Clear()
}

#endregion

#region Main Application

try {
    # Load XAML
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]$xaml)
    $script:window = [Windows.Markup.XamlReader]::Load($reader)
    
    # Set window title with version
    $script:window.Title = "$($script:AppName) v$($script:AppVersion)"

    # Get UI elements
    $script:txtPassword = $window.FindName("txtPassword")
    $script:btnShowPassword = $window.FindName("btnShowPassword")
    $script:chkRememberPassword = $window.FindName("chkRememberPassword")
    $script:btnSelectFiles = $window.FindName("btnSelectFiles")
    $script:btnSelectFolder = $window.FindName("btnSelectFolder")
    $script:btnClearSelection = $window.FindName("btnClearSelection")
    $script:txtSelectionCount = $window.FindName("txtSelectionCount")
    $script:lstFiles = $window.FindName("lstFiles")
    $script:btnEncrypt = $window.FindName("btnEncrypt")
    $script:btnDecrypt = $window.FindName("btnDecrypt")
    $script:btnSecureDelete = $window.FindName("btnSecureDelete")
    
    # Auto-Encrypt elements
    $script:chkAutoEncryptEnabled = $window.FindName("chkAutoEncryptEnabled")
    $script:txtMonitorFolder = $window.FindName("txtMonitorFolder")
    $script:btnBrowseMonitor = $window.FindName("btnBrowseMonitor")
    $script:txtIncludeExtensions = $window.FindName("txtIncludeExtensions")
    $script:txtExcludeExtensions = $window.FindName("txtExcludeExtensions")
    $script:txtAutoEncryptLog = $window.FindName("txtAutoEncryptLog")
    $script:btnClearLog = $window.FindName("btnClearLog")
    $script:btnStartMonitoring = $window.FindName("btnStartMonitoring")
    $script:btnStopMonitoring = $window.FindName("btnStopMonitoring")
    
    # Settings elements
    $script:cmbAlgorithm = $window.FindName("cmbAlgorithm")
    $script:cmbIterations = $window.FindName("cmbIterations")
    $script:txtEncryptedExtension = $window.FindName("txtEncryptedExtension")
    $script:chkDeleteOriginal = $window.FindName("chkDeleteOriginal")
    $script:chkSecureDelete = $window.FindName("chkSecureDelete")
    $script:chkDeleteEncrypted = $window.FindName("chkDeleteEncrypted")
    $script:chkPreserveTimestamps = $window.FindName("chkPreserveTimestamps")
    $script:chkOneDrive = $window.FindName("chkOneDrive")
    $script:txtOneDrivePath = $window.FindName("txtOneDrivePath")
    $script:chkGoogleDrive = $window.FindName("chkGoogleDrive")
    $script:txtGoogleDrivePath = $window.FindName("txtGoogleDrivePath")
    $script:chkDropbox = $window.FindName("chkDropbox")
    $script:txtDropboxPath = $window.FindName("txtDropboxPath")
    $script:chkSyncToCloud = $window.FindName("chkSyncToCloud")
    $script:txtCloudSubfolder = $window.FindName("txtCloudSubfolder")
    $script:btnSaveSettings = $window.FindName("btnSaveSettings")
    $script:btnResetSettings = $window.FindName("btnResetSettings")
    
    # Progress/Status elements
    $script:txtProgressStatus = $window.FindName("txtProgressStatus")
    $script:txtProgressDetail = $window.FindName("txtProgressDetail")
    $script:progressBar = $window.FindName("progressBar")
    $script:txtLiveLog = $window.FindName("txtLiveLog")
    $script:btnOpenLogs = $window.FindName("btnOpenLogs")
    $script:btnOpenCloudDest = $window.FindName("btnOpenCloudDest")
    $script:txtHelpFooter = $window.FindName("txtHelpFooter")
    $script:txtStatus = $window.FindName("txtStatus")
    $script:txtTimestamp = $window.FindName("txtTimestamp")
    
    # Initialize logging + UI
    Initialize-Logging
    Initialize-UI
    # Set help footer text
    if ($script:txtHelpFooter) {
        $script:txtHelpFooter.Text = "$($script:AppName) v$($script:AppVersion) ($($script:BuildDate))"
    }


    
    # Wire up event handlers
    $btnShowPassword.Add_Click({ Show-PasswordToggle })
    $btnSelectFiles.Add_Click({ Select-FilesForEncryption })
    $btnSelectFolder.Add_Click({ Select-FolderForEncryption })
    $btnClearSelection.Add_Click({ Clear-FileSelection })
    $btnEncrypt.Add_Click({ Start-EncryptionProcess })
    $btnDecrypt.Add_Click({ Start-DecryptionProcess })
    $btnSecureDelete.Add_Click({ Start-SecureDeleteProcess })
    
    # Auto-Encrypt events
    $btnBrowseMonitor.Add_Click({ Select-MonitorFolder })
    $btnClearLog.Add_Click({ Clear-MonitorLog })
    $btnStartMonitoring.Add_Click({ Start-FileMonitoring })
    $btnStopMonitoring.Add_Click({ Stop-FileMonitoring })
    
    $chkAutoEncryptEnabled.Add_Checked({
        if ($script:txtMonitorFolder.Text.Length -gt 0 -and $script:txtPassword.Password.Length -gt 0) {
            $script:btnStartMonitoring.IsEnabled = $true
        }
    })
    
    $chkAutoEncryptEnabled.Add_Unchecked({
        $script:btnStartMonitoring.IsEnabled = $false
        if ($script:monitoringActive) {
            Stop-FileMonitoring
        }
    })
    
    # Logs
    if ($script:btnOpenLogs) {
        $script:btnOpenLogs.Add_Click({
            try {
                if ($script:LogDir -and (Test-Path $script:LogDir)) {
                    Start-Process explorer.exe $script:LogDir
                } elseif ($script:LogFilePath) {
                    Start-Process explorer.exe (Split-Path -Path $script:LogFilePath -Parent)
                } else {
                    [System.Windows.MessageBox]::Show("Log folder not initialized yet.", "Logs",
                        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
                }

    # Open cloud destination folder(s)
    if ($script:btnOpenCloudDest) {
        $script:btnOpenCloudDest.Add_Click({
            try {
                $sub = Get-CloudSubfolder

                $opened = 0
                $targets = @()

                # OneDrive
                if ($script:chkOneDrive -and $script:chkOneDrive.IsChecked -and $script:txtOneDrivePath) {
                    $root = Normalize-CloudPath -Path $script:txtOneDrivePath.Text
                    if (-not [string]::IsNullOrWhiteSpace($root)) {
                        $targets += (Join-Path $root $sub)
                    }
                }

                # Google Drive
                if ($script:chkGoogleDrive -and $script:chkGoogleDrive.IsChecked -and $script:txtGoogleDrivePath) {
                    $root = Normalize-CloudPath -Path $script:txtGoogleDrivePath.Text
                    if (-not [string]::IsNullOrWhiteSpace($root)) {
                        $targets += (Join-Path $root $sub)
                    }
                }

                # Dropbox
                if ($script:chkDropbox -and $script:chkDropbox.IsChecked -and $script:txtDropboxPath) {
                    $root = Normalize-CloudPath -Path $script:txtDropboxPath.Text
                    if (-not [string]::IsNullOrWhiteSpace($root)) {
                        $targets += (Join-Path $root $sub)
                    }
                }

                $targets = $targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

                if (-not $targets -or $targets.Count -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No cloud providers are selected (or their paths are empty).`n`nSelect a provider and try again.",
                        "Cloud Destination",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Information
                    ) | Out-Null
                    return
                }

                foreach ($t in $targets) {
                    if (-not (Test-Path $t)) {
                        New-Item -ItemType Directory -Path $t -Force | Out-Null
                    }
                    Start-Process explorer.exe $t
                    $opened++
                }

                if ($opened -eq 0) {
                    [System.Windows.MessageBox]::Show(
                        "No cloud destination folder could be opened.",
                        "Cloud Destination",
                        [System.Windows.MessageBoxButton]::OK,
                        [System.Windows.MessageBoxImage]::Warning
                    ) | Out-Null
                }
            }
            catch {
                [System.Windows.MessageBox]::Show(
                    "Failed to open cloud destination.`n`n$($_.Exception.Message)",
                    "Cloud Destination",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Error
                ) | Out-Null
            }
        })
    }
            } catch {
                [System.Windows.MessageBox]::Show("Unable to open log folder: $($_.Exception.Message)", "Logs",
                    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
            }
        })
    }

    # Settings events
    $btnSaveSettings.Add_Click({
        $script:settings.Iterations = [int]$script:cmbIterations.SelectedItem.Tag
        $script:settings.EncryptedExtension = $script:txtEncryptedExtension.Text
        $script:settings.CloudSubfolder = (Get-CloudSubfolder)
        $script:settings.DeleteOriginal = $script:chkDeleteOriginal.IsChecked
        $script:settings.SecureDelete = $script:chkSecureDelete.IsChecked
        $script:settings.DeleteEncrypted = $script:chkDeleteEncrypted.IsChecked
        $script:settings.PreserveTimestamps = $script:chkPreserveTimestamps.IsChecked
        
        [System.Windows.MessageBox]::Show("Settings saved successfully!", "Settings", 
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })
    
    $btnResetSettings.Add_Click({
        $result = [System.Windows.MessageBox]::Show("Reset all settings to defaults?", "Confirm Reset", 
            [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        
        if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
            Initialize-UI
            [System.Windows.MessageBox]::Show("Settings reset to defaults.", "Settings", 
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
    
    # Cleanup on close
    $window.Add_Closing({
        if ($script:monitoringActive) {
            Stop-FileMonitoring
        }
    })
    
    Write-Log "$($script:AppName) v$($script:AppVersion) ($($script:BuildDate)) started" -Level Success
    
    # Show window
    $window.ShowDialog() | Out-Null
}
catch {
    [System.Windows.MessageBox]::Show("Fatal error: $_", "Error", 
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    Write-Log "Fatal error: $_" -Level Error
}

#endregion
