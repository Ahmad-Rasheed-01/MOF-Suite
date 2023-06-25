# Import multiple libraries.
import platform
import subprocess
import sys
from PyQt5.QtWidgets import QApplication, QDialog, QFormLayout, QLineEdit, QVBoxLayout, QPushButton, QMessageBox, QMenuBar, QMenu, QAction

# Create a class for the MOF Suite application.
class MOFSuite(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MOF Suite")
        self.layout = QVBoxLayout()
        self.form_layout = QFormLayout()

        # Create QLineEdit widgets for different case details.
        self.investigator_name = QLineEdit()
        self.case_number = QLineEdit()
        self.evidence_number = QLineEdit()
        self.evidence_details = QLineEdit()
        self.date = QLineEdit()

        # Add the QLineEdit widgets to the form layout.
        self.form_layout.addRow("Investigator Name:", self.investigator_name)
        self.form_layout.addRow("Case Number:", self.case_number)
        self.form_layout.addRow("Evidence Number:", self.evidence_number)
        self.form_layout.addRow("Evidence Details:", self.evidence_details)
        self.form_layout.addRow("Date:", self.date)

        # Create a button to save case details.
        self.save_button = QPushButton("Save Case Details")
        self.save_button.clicked.connect(self.save_case_details)

        # Create a button to detect the operating system.
        self.detect_os_button = QPushButton("Detect OS")
        self.detect_os_button.clicked.connect(self.detect_os)

        # Add the form layout and buttons to the main layout.
        self.layout.addLayout(self.form_layout)
        self.layout.addWidget(self.save_button)
        self.layout.addWidget(self.detect_os_button)

        self.setLayout(self.layout)
        self.setFixedHeight(300)
        self.setFixedWidth(420)

    # This code initializes a menu bar for a GUI application.
        self.init_menu()

    def init_menu(self):
        menu_bar = QMenuBar()
        self.layout.setMenuBar(menu_bar)

        # File menu
        file_menu = QMenu("File", self)
        menu_bar.addMenu(file_menu)

        # Create an "Exit" QAction and add it to the file menu.
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Operating System Details menu
        os_details_menu = QMenu("OS Details", self)
        menu_bar.addMenu(os_details_menu)

        # Create a menu item for generating a OS basic information report.
        os_info_action = QAction("OS Information", self)
        os_info_action.triggered.connect(self.generate_os_info_report)
        os_details_menu.addAction(os_info_action)

        # Create a menu item for generating a installed softwares report.
        installed_softwares_action = QAction("Installed Softwares", self)
        installed_softwares_action.triggered.connect(
            self.generate_installed_softwares_report)
        os_details_menu.addAction(installed_softwares_action)

        # Create a menu item for generating a patches list report.
        patches_list_action = QAction("Patches List", self)
        patches_list_action.triggered.connect(
            self.generate_patches_list_report)
        os_details_menu.addAction(patches_list_action)

        # Users menu
        users_menu = QMenu("Users", self)
        menu_bar.addMenu(users_menu)

        # Create a menu item for generating a user list report.
        user_list_action = QAction("User List", self)
        user_list_action.triggered.connect(self.generate_user_list_report)
        users_menu.addAction(user_list_action)

        # Create a menu item for generating a user groups list report.
        groups_action = QAction("Groups", self)
        groups_action.triggered.connect(self.generate_groups_report)
        users_menu.addAction(groups_action)

        # Event Logs menu
        event_logs_menu = QMenu("Event Logs", self)
        menu_bar.addMenu(event_logs_menu)

        # Create a menu item for generating a system logs report.
        system_logs_action = QAction("System Logs", self)
        system_logs_action.triggered.connect(self.generate_system_logs_report)
        event_logs_menu.addAction(system_logs_action)

        # Create a menu item for generating a running processes report.
        executed_processes_action = QAction("Executed Processes", self)
        executed_processes_action.triggered.connect(
            self.generate_executed_processes_report)
        event_logs_menu.addAction(executed_processes_action)

        # Create a menu item for generating a users logon report.
        logon_events_action = QAction("Logon Events", self)
        logon_events_action.triggered.connect(
            self.generate_logon_events_report)
        event_logs_menu.addAction(logon_events_action)

        # Create a menu item for generating a log report of installed packages.
        installation_logs_action = QAction("Installation Logs", self)
        installation_logs_action.triggered.connect(
            self.generate_installation_logs_report)
        event_logs_menu.addAction(installation_logs_action)

        # Create a menu item for generating a user logs report.
        user_logs_action = QAction("User Logs", self)
        user_logs_action.triggered.connect(self.generate_user_logs_report)
        event_logs_menu.addAction(user_logs_action)

        # Create a menu item for generating a kernel network logs report.
        kernel_network_logs_action = QAction("Kernel Network Logs", self)
        kernel_network_logs_action.triggered.connect(
            self.generate_kernel_network_logs_report)
        event_logs_menu.addAction(kernel_network_logs_action)

        # Drives menu
        drives_menu = QMenu("Drives", self)
        menu_bar.addMenu(drives_menu)

        # Create a menu item for generating a file system related report.
        root_file_system_action = QAction("File System", self)
        root_file_system_action.triggered.connect(
            self.generate_file_system_report)
        drives_menu.addAction(root_file_system_action)

        # Create a menu item for generating a list of drives on operating system.
        drives_list_action = QAction("Drives List", self)
        drives_list_action.triggered.connect(self.generate_drives_list_report)
        drives_menu.addAction(drives_list_action)

        # Devices submenu
        usb_submenu = QMenu("USB Devices", self)

        # Create a submenu item for generating a attached USB devices list report.
        usb_devices_action = QAction("USB Devices", self)
        usb_devices_action.triggered.connect(self.generate_usb_devices_report)
        usb_submenu.addAction(usb_devices_action)

        # Create a submenu item for generating a detailed USB drives list report.
        usb_devices_detailed_action = QAction("USB Devices Detailed", self)
        usb_devices_detailed_action.triggered.connect(
            self.generate_usb_devices_detailed_report)
        usb_submenu.addAction(usb_devices_detailed_action)

        # Create a submenu item for generating a USB drives attach history report.
        usb_devices_history_action = QAction("USB Devices History", self)
        usb_devices_history_action.triggered.connect(
            self.generate_usb_devices_history_report)
        usb_submenu.addAction(usb_devices_history_action)

        drives_menu.addMenu(usb_submenu)

        # Create a menu item for generating a report of files created during last 7 days.
        file_created_action = QAction("Files Created (NA)", self)
        file_created_action.triggered.connect(
            self.generate_file_created_report)
        drives_menu.addAction(file_created_action)

        # Suspicious Files submenu
        suspicious_submenu = QMenu("Suspicious Files", self)

        # Create a submenu item for generating a report of ELFs (Executables and Linkable Files) using regular expression.
        suspicious_elf_action = QAction("Suspicious ELFs", self)
        suspicious_elf_action.triggered.connect(
            self.generate_suspicious_elf_report)
        suspicious_submenu.addAction(suspicious_elf_action)

        # Create a submenu item for generating a report of suspicious image files.
        suspicious_images_action = QAction("Suspicious Images", self)
        suspicious_images_action.triggered.connect(
            self.generate_suspicious_images_report)
        suspicious_submenu.addAction(suspicious_images_action)

        drives_menu.addMenu(suspicious_submenu)

        # Networks menu
        networks_menu = QMenu("Networks", self)
        menu_bar.addMenu(networks_menu)

        # Create a menu item for generating an Internet Protocol Configuration report.
        ip_configurations_action = QAction("IP Configurations", self)
        ip_configurations_action.triggered.connect(
            self.generate_ip_configurations_report)
        networks_menu.addAction(ip_configurations_action)

        # Create a menu item for generating a report of saved wifi networks.
        saved_connections_action = QAction("Saved Connections (root)", self)
        saved_connections_action.triggered.connect(
            self.generate_saved_connections_report)
        networks_menu.addAction(saved_connections_action)

        # Create a menu item for generating Address Resolution Protocol (ARP) cache report.
        arp_cache_action = QAction("ARP Cache", self)
        arp_cache_action.triggered.connect(self.generate_arp_cache_report)
        networks_menu.addAction(arp_cache_action)

        # Create a menu item for generating a Domain Name System (DNS) cache report.
        dns_cache_action = QAction("DNS Cache", self)
        dns_cache_action.triggered.connect(self.generate_dns_cache_report)
        networks_menu.addAction(dns_cache_action)

        # Create a menu item for generating a report of active tcp connections.
        tcp_connections_action = QAction("TCP Connections", self)
        tcp_connections_action.triggered.connect(
            self.generate_tcp_connections_report)
        networks_menu.addAction(tcp_connections_action)

        # Create a menu item for generating a list of rules configured by firewall.
        firewall_rules_action = QAction("Firewall Rules (root)", self)
        firewall_rules_action.triggered.connect(
            self.generate_firewall_rules_report)
        networks_menu.addAction(firewall_rules_action)

        # Create a menu item for generating a report of all system services with status e.g. enabled, disabled.
        systemctl_services_action = QAction("Systemctl Services", self)
        systemctl_services_action.triggered.connect(
            self.generate_systemctl_services_report)
        networks_menu.addAction(systemctl_services_action)

    # Method to get the entered case details
    def save_case_details(self):
        case_details = f"Investigator Name: {self.investigator_name.text()}\n" \
                       f"Case Number: {self.case_number.text()}\n" \
                       f"Evidence Number: {self.evidence_number.text()}\n" \
                       f"Evidence Details: {self.evidence_details.text()}\n" \
                       f"Date: {self.date.text()}"

        # Save case details to the file
        with open("0. Case_Details.txt", "w") as file:
            file.write(case_details)
        QMessageBox.information(
            self, "Saved", "Case details saved successfully.")

    # Method to detect the Operating System type
    def detect_os(self):
        system = platform.system()
        if system == "Windows":
            QMessageBox.information(
                self, "OS Detected", "Windows Operating System Detected")
        elif system == "Linux":
            QMessageBox.information(
                self, "OS Detected", "Linux Operating System Detected")
        else:
            QMessageBox.information(
                self, "OS Detected", "Unknown operating system")

    def run_command(self, command, output_file):
        try:
            # Execute the command and capture the output
            output = subprocess.check_output(
                command, shell=True, universal_newlines=True)
            # Write the output to the specified file
            with open(output_file, "w") as file:
                file.write(output)
            QMessageBox.information(
                self, "Report Generated", f"Report generated successfully: {output_file}")
        except subprocess.CalledProcessError:
            QMessageBox.warning(
                self, "Error", f"Failed to generate report: {output_file}")

    # Method to get operating system information
    def generate_os_info_report(self):
        command = "lsb_release -a"
        self.run_command(command, "1. OS_Info.txt")

   # This method generates a report of all the installed software on a Debian-based system.

    def generate_installed_softwares_report(self):
        command = "dpkg --list"
        self.run_command(command, "2. Installed_Softwares.txt")

    # Method to get a list of all installed patches/updates.
    def generate_patches_list_report(self):
        command = "dpkg --get-selections | grep -E 'install|hold'"
        self.run_command(command, "3. Installed_Patches.txt")

    # Method to get user list.
    def generate_user_list_report(self):
        command = "getent passwd | awk -F: '{OFS=\":\"; print $1, $3, $4, $5, $6, $7}' | column -s\":\" -t"
        self.run_command(command, "4. User_list.txt")

    # Method to get a list of all groups.
    def generate_groups_report(self):
        command = "getent group | awk -F: '{printf \"%-10s %-5s %s\\n\", $1, $3, $4}' | column -t"
        self.run_command(command, "5. Groups.txt")

    # Method to get report of system logs.
    def generate_system_logs_report(self):
        command = "cat /var/log/syslog"
        self.run_command(command, "6.Sys_Logs.txt")

    # Method to get a list of all running processes.
    def generate_executed_processes_report(self):
        command = "ps -eo pid,ppid,user,start,cmd,ag_id,group,gid,policy,size"
        self.run_command(command, "7. Executed_Processes.txt")

    # Method to get report of user login history.
    def generate_logon_events_report(self):
        command = "last"
        self.run_command(command, "8. Logon_Events.txt")

    # Method to get report of installed debian packages.
    def generate_installation_logs_report(self):
        command = "cat /var/log/dpkg.log"
        self.run_command(command, "9. Installation_logs.txt")

    # Method to get a report of user logs.
    def generate_user_logs_report(self):
        command = "cat /var/log/auth.log"
        self.run_command(command, "10. User_logs.txt")

    # Method to get a report of kernel network logs.
    def generate_kernel_network_logs_report(self):
        command = "dmesg"
        self.run_command(command, "11. Kernel_Network_Logs.txt")

    # Method to generate a report about file system including some basic information.
    def generate_file_system_report(self):
        command = "df -T -H /"
        self.run_command(command, "12. Root_File_System.txt")

    # Method to get a list of all drives with some basic information.
    def generate_drives_list_report(self):
        command = "lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,WWN"
        self.run_command(command, "13. Drives_List.txt")

    # Method to get USB Devices list.
    def generate_usb_devices_report(self):
        command = "lsusb"
        self.run_command(command, "14a. USB_Devices.txt")

    # Method to get detailed USB devices list.
    def generate_usb_devices_detailed_report(self):
        command = "usb-devices"
        self.run_command(command, "14b. USB_Devices_Detailed.txt")

    # Method to generate a report of USB devices history
    def generate_usb_devices_history_report(self):
        command = "cat /var/log/syslog | grep -i 'USB\|drive'"
        self.run_command(command, "14c. USB_Devices_History.txt")

    # Method to get a list of files created during last 7 days.
    def generate_file_created_report(self):
        command = "find / -type f -ctime 7 2>/dev/null"
        self.run_command(command, "15. Created_Files (-7 Days).txt")

    # Method to get a list of all suspicious ELFs.
    def generate_suspicious_elf_report(self):
        command = "find / -regex '.*\\.\(jpg\|gif\|png\|jpeg\)' -type f -exec file -p '{}' \; 2>/dev/null | grep ELF | cut -d':' -f1"
        self.run_command(command, "16a. Suspicious_ELFs.txt")

    # Method to get a list of all suspicious image files.
    def generate_suspicious_images_report(self):
        command = "find / -regex '.*\\.\(jpg\|gif\|png\|jpeg\)' -type f -exec file -p '{}' \; 2>/dev/null | grep -v image"
        self.run_command(command, "16b. Suspicious_Images.txt")

    # Method to get a report of IP Configurations including network adapters.
    def generate_ip_configurations_report(self):
        command = "ifconfig -a"
        self.run_command(command, "17. IP_Configurations.txt")

    # Method to get a detailed list of all saved wifi networks.
    def generate_saved_connections_report(self):
        command = "cat /etc/NetworkManager/system-connections/*"
        self.run_command(command, "18. Saved_Connections.txt")

    # Method to get a report of ARP cache.
    def generate_arp_cache_report(self):
        command = "arp -a"
        self.run_command(command, "19. ARP_Cache.txt")

    # Method to get a report of DNS cache.
    def generate_dns_cache_report(self):
        command = "cat /etc/resolv.conf"
        self.run_command(command, "20. DNS_Cache.txt")

    # Method to get a list of all active TCP connections.
    def generate_tcp_connections_report(self):
        command = "netstat -atn"
        self.run_command(command, "21. TCP_Connections.txt")

    # Method to get a list of all configured firewall rules.
    def generate_firewall_rules_report(self):
        command = "iptables -L"
        self.run_command(command, "22. Firewall_Rules.txt")

    # Method to get a list of all system services alongwith status e.g. enabled, disabled.
    def generate_systemctl_services_report(self):
        command = "systemctl list-unit-files"
        self.run_command(command, "23. Systemctl_Services.txt")


'''This code block is the entry point of the application. It creates a QApplication object, initializes the MOFSuite dialog, shows it, and starts the application event loop. When the event loop is exited, the application is terminated.'''
if __name__ == "__main__":
    app = QApplication(sys.argv)
    dialog = MOFSuite()
    dialog.show()
    sys.exit(app.exec_())
