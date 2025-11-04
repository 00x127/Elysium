class VulnChecker:
    def __init__(self):
        self.known_issues = {
            21: ['Anonymous FTP', 'vsftpd 2.3.4 backdoor'],
            22: ['Weak SSH algorithms', 'Default credentials'],
            23: ['Telnet plaintext', 'No encryption'],
            3306: ['MySQL default root', 'No password'],
            3389: ['RDP BlueKeep (CVE-2019-0708)', 'Weak credentials'],
            5900: ['VNC no authentication', 'Weak password'],
            6379: ['Redis no auth', 'Unprotected instance']
        }

    def check(self, target, port, service):
        issues = []

        if port in self.known_issues:
            issues.extend(self.known_issues[port])

        return issues
