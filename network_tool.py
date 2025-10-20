import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import requests
import subprocess
import re
import platform
import uuid
import os
import sys
import random

class NetworkInfoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Information Tool")
        self.root.geometry("900x700")
        self.root.configure(bg='black')
        self.root.resizable(True, True)
        
        # Setup UI
        self.setup_ui()
        
    def setup_ui(self):
        # Main title
        title_label = tk.Label(self.root, text="Network Information Tool", 
                              font=("Arial", 18, "bold"), fg="#00FF00", bg='black')
        title_label.pack(pady=20)
        
        # Main frame for buttons and results
        main_frame = tk.Frame(self.root, bg='black')
        main_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Public IP Section
        public_ip_frame = tk.Frame(main_frame, bg='black')
        public_ip_frame.pack(fill="x", pady=8)
        
        public_ip_btn = tk.Button(public_ip_frame, text="Get Public IP", 
                                 font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                                 command=self.get_public_ip, width=15, height=1)
        public_ip_btn.pack(side="left", padx=10)
        
        self.public_ip_value = tk.Label(public_ip_frame, text="Click button to get", 
                                       font=("Arial", 12), fg="#00FF00", bg='black', width=25)
        self.public_ip_value.pack(side="left", padx=10)
        
        # Local IP Section
        local_ip_frame = tk.Frame(main_frame, bg='black')
        local_ip_frame.pack(fill="x", pady=8)
        
        local_ip_btn = tk.Button(local_ip_frame, text="Get Local IP", 
                                font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                                command=self.get_local_ip, width=15, height=1)
        local_ip_btn.pack(side="left", padx=10)
        
        self.local_ip_value = tk.Label(local_ip_frame, text="Click button to get", 
                                      font=("Arial", 12), fg="#00FF00", bg='black', width=25)
        self.local_ip_value.pack(side="left", padx=10)
        
        # MAC Address Section
        mac_frame = tk.Frame(main_frame, bg='black')
        mac_frame.pack(fill="x", pady=8)
        
        mac_btn = tk.Button(mac_frame, text="Get MAC Address", 
                           font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                           command=self.get_mac_address, width=15, height=1)
        mac_btn.pack(side="left", padx=10)
        
        self.mac_value = tk.Label(mac_frame, text="Click button to get", 
                                 font=("Arial", 12), fg="#00FF00", bg='black', width=25)
        self.mac_value.pack(side="left", padx=10)
        
        # WiFi Password Section
        wifi_frame = tk.Frame(main_frame, bg='black')
        wifi_frame.pack(fill="x", pady=8)
        
        wifi_btn = tk.Button(wifi_frame, text="Get WiFi Password", 
                            font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                            command=self.get_wifi_password_auto_root, width=15, height=1)
        wifi_btn.pack(side="left", padx=10)
        
        self.wifi_value = tk.Label(wifi_frame, text="Click button to get", 
                                  font=("Arial", 12), fg="#00FF00", bg='black', width=25)
        self.wifi_value.pack(side="left", padx=10)
        
        # Connected WiFi Name
        wifi_name_frame = tk.Frame(main_frame, bg='black')
        wifi_name_frame.pack(fill="x", pady=5)
        
        wifi_name_label = tk.Label(wifi_name_frame, text="Connected WiFi:", 
                                  font=("Arial", 11, "bold"), fg="#00FF00", bg='black')
        wifi_name_label.pack(side="left", padx=10)
        
        self.wifi_name_value = tk.Label(wifi_name_frame, text="Not checked", 
                                       font=("Arial", 11), fg="#00FF00", bg='black')
        self.wifi_name_value.pack(side="left", padx=10)
        
        # Refresh All Button
        refresh_btn = tk.Button(self.root, text="Refresh All Information", 
                               font=("Arial", 12, "bold"), fg="black", bg="#00FF00",
                               command=self.refresh_all, width=20, height=1)
        refresh_btn.pack(pady=15)
        
        # Results Display Area
        results_label = tk.Label(self.root, text="Results Display:", 
                               font=("Arial", 14, "bold"), fg="#00FF00", bg='black')
        results_label.pack(pady=(20, 5))
        
        # Create scrolled text area for results
        self.results_text = scrolledtext.ScrolledText(
            self.root, 
            wrap=tk.WORD, 
            width=80, 
            height=15,
            font=("Consolas", 10),
            bg='black',
            fg='#00FF00',
            insertbackground='#00FF00'
        )
        self.results_text.pack(pady=10, padx=20, fill="both", expand=True)
        self.results_text.config(state=tk.DISABLED)
        
        # System info with root status
        root_status = "Running as ROOT" if self.is_root() else "Running as USER"
        system_label = tk.Label(self.root, 
                               text=f"OS: {platform.system()} | {root_status} | Python {sys.version_info.major}.{sys.version_info.minor}", 
                               font=("Arial", 10), fg="#00FF00", bg='black')
        system_label.pack(side="bottom", pady=10)
        
        # Display initial root status
        self.display_result(f"Application started - {root_status}\n{'='*50}")
    
    def is_root(self):
        """Check if running as root"""
        try:
            return os.geteuid() == 0
        except:
            return False
    
    def get_public_ip(self):
        """Get Public IP from new API connection each time"""
        try:
            self.public_ip_value.config(text="Loading...")
            self.root.update()
            
            api_services = [
                'https://api.ipify.org',
                'https://ident.me',
                'https://checkip.amazonaws.com',
                'https://ipinfo.io/ip',
                'https://icanhazip.com'
            ]
            
            selected_api = random.choice(api_services)
            
            headers = {
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
            
            response = requests.get(selected_api, timeout=10, headers=headers)
            public_ip = response.text.strip()
            
            if public_ip and self.is_valid_ip(public_ip):
                self.public_ip_value.config(text=public_ip)
                self.display_result(f"Public IP: {public_ip}\nSource: {selected_api}\n{'-'*50}")
            else:
                self.public_ip_value.config(text="Failed")
                self.display_result("Failed to get Public IP")
                
        except Exception as e:
            self.public_ip_value.config(text="Error")
            self.display_result(f"Public IP Error: {str(e)}")
    
    def get_local_ip(self):
        """Get real Local IP on current network"""
        try:
            self.local_ip_value.config(text="Loading...")
            self.root.update()
            
            local_ip = self.get_current_network_ip()
            
            if local_ip:
                self.local_ip_value.config(text=local_ip)
                self.display_result(f"Local IP: {local_ip}\n{'-'*50}")
            else:
                self.local_ip_value.config(text="Not available")
                self.display_result("Local IP: Not available")
                
        except Exception as e:
            self.local_ip_value.config(text="Error")
            self.display_result(f"Local IP Error: {str(e)}")
    
    def get_current_network_ip(self):
        """Get real IP address on current network"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            try:
                hostname = socket.gethostname()
                all_ips = socket.gethostbyname_ex(hostname)[2]
                valid_ips = [ip for ip in all_ips if not ip.startswith('127.') and not ip.startswith('169.254')]
                return valid_ips[0] if valid_ips else all_ips[0] if all_ips else "Not available"
            except:
                return "Not available"
    
    def get_mac_address(self):
        """Get MAC Address"""
        try:
            self.mac_value.config(text="Loading...")
            self.root.update()
            
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            self.mac_value.config(text=mac)
            self.display_result(f"MAC Address: {mac}\n{'-'*50}")
        except:
            self.mac_value.config(text="Not available")
            self.display_result("MAC Address: Not available")
    
    def get_wifi_password_auto_root(self):
        """Get WiFi password with proper root handling"""
        try:
            self.wifi_value.config(text="Loading...")
            self.wifi_name_value.config(text="Loading...")
            self.root.update()
            
            system = platform.system()
            
            if system == "Linux":
                if not self.is_root():
                    self.display_result("ERROR: Root access required for WiFi passwords on Linux")
                    self.wifi_value.config(text="Need ROOT")
                    self.wifi_name_value.config(text="Need ROOT")
                    messagebox.showerror(
                        "Root Access Required", 
                        "You must run this application as root to get WiFi passwords.\n\n"
                        "Please close and run with:\n\n"
                        "sudo python3 " + os.path.basename(__file__)
                    )
                    return
                
                # If we have root, get WiFi info
                ssid, password = self.get_wifi_info_linux_with_root()
                
            elif system == "Windows":
                ssid, password = self.get_wifi_info_windows()
            else:
                ssid, password = None, "Unsupported OS"
            
            if ssid:
                self.wifi_name_value.config(text=ssid)
                self.wifi_value.config(text=password)
                self.display_result(f"WiFi Name: {ssid}\nWiFi Password: {password}\n{'-'*50}")
            else:
                self.wifi_name_value.config(text="Not connected")
                self.wifi_value.config(text=password)
                self.display_result(f"WiFi Status: {password}")
                
        except Exception as e:
            self.wifi_value.config(text="Error")
            self.wifi_name_value.config(text="Error")
            self.display_result(f"WiFi Password Error: {str(e)}")
    
    def get_wifi_info_windows(self):
        """Get WiFi info on Windows"""
        try:
            command = "netsh wlan show interfaces"
            interfaces_output = subprocess.check_output(command, shell=True, text=True, encoding='utf-8', errors='ignore')
            
            ssid_match = re.search(r"SSID\s*:\s*(.*)", interfaces_output)
            if not ssid_match:
                return None, "Not connected to WiFi"
            
            connected_ssid = ssid_match.group(1).strip()
            
            command = f'netsh wlan show profile name="{connected_ssid}" key=clear'
            profile_output = subprocess.check_output(command, shell=True, text=True, encoding='utf-8', errors='ignore')
            
            key_match = re.search(r"Key Content\s*:\s*(.*)", profile_output)
            if key_match:
                return connected_ssid, key_match.group(1).strip()
            else:
                return connected_ssid, "Password not available"
                
        except Exception as e:
            return None, f"Error: {str(e)}"
    
    def get_wifi_info_linux_with_root(self):
        """Get WiFi info on Linux with root privileges"""
        try:
            # Get connected SSID
            command = "iwgetid -r"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0 or not result.stdout.strip():
                return None, "Not connected to WiFi"
            
            connected_ssid = result.stdout.strip()
            self.display_result(f"Connected to: {connected_ssid}")
            
            # Try multiple methods to get WiFi password with root
            password_methods = [
                # Method 1: NetworkManager
                f"cat /etc/NetworkManager/system-connections/'{connected_ssid}' 2>/dev/null | grep -i psk",
                f"cat /etc/NetworkManager/system-connections/{connected_ssid} 2>/dev/null | grep -i psk",
                
                # Method 2: WPA Supplicant
                f"cat /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null | grep -A10 -B2 '{connected_ssid}' | grep -i psk",
                
                # Method 3: Direct file reading
                f"grep -r 'psk=' /etc/NetworkManager/system-connections/ 2>/dev/null | grep -i '{connected_ssid}'",
                
                # Method 4: Using nmcli (requires NetworkManager)
                f"nmcli -s -g 802-11-wireless-security.psk connection show '{connected_ssid}' 2>/dev/null"
            ]
            
            for i, cmd in enumerate(password_methods, 1):
                try:
                    self.display_result(f"Trying method {i}: {cmd}")
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and result.stdout.strip():
                        output = result.stdout.strip()
                        self.display_result(f"Method {i} output: {output}")
                        
                        # Extract password from different formats
                        if "psk=" in output:
                            if "=" in output:
                                password = output.split("psk=")[1].strip()
                                if '"' in password:
                                    password = password.split('"')[1]
                                else:
                                    password = password.split()[0] if ' ' in password else password
                                password = password.strip('"').strip()
                                if password:
                                    return connected_ssid, password
                        
                        # If output looks like just the password
                        if output and len(output) >= 8 and ' ' not in output:
                            return connected_ssid, output
                            
                except Exception as e:
                    self.display_result(f"Method {i} failed: {str(e)}")
                    continue
            
            return connected_ssid, "Password not found in system files"
                
        except Exception as e:
            self.display_result(f"Linux WiFi Error: {str(e)}")
            return None, f"Error: {str(e)}"
    
    def display_result(self, text):
        """Display results in the text area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_results(self):
        """Clear results display"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def refresh_all(self):
        """Refresh all information"""
        self.clear_results()
        self.display_result("REFRESHING ALL INFORMATION...\n" + "="*40)
        self.get_public_ip()
        self.get_local_ip()
        self.get_mac_address()
        # Don't auto-refresh WiFi password as it needs root confirmation

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkInfoApp(root)
    root.mainloop()
