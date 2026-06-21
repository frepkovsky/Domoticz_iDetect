import os
import shlex
import subprocess
from datetime import datetime

import Domoticz
from trackers.tracker_base import tracker


class ssh_tracker(tracker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trackerscript = ''
        self.sshbin = 'ssh'
        self.connected = False
        self.strict_host_key_checking = False
        self.connect_timeout = 5

        if self.tracker_port is None:
            self.tracker_port = 22

        Domoticz.Debug(self.tracker_ip + ' Tracker is of the ssh kind')
        self.ssh_connect()

    def logger(self, message):
        Domoticz.Log(message)

    def poll_present_tag_ids(self):
        Domoticz.Debug(self.tracker_ip + ' Start poll and return results to ' + str(self.receiver_callback))
        success, raw_data = self.getfromssh(self.trackerscript)
        if not success:
            self.error_count = self.error_count + 1
            Domoticz.Log(self.tracker_ip + ' Could not be polled')
            return

        self.error_count = 0
        self.receiver_callback(raw_data)

    def prepare_for_polling(self):
        # Should be implemented in specific tracker
        Domoticz.Debug(self.tracker_ip + ' Has no prepare_for_pollling method.')
        return True

    def _known_hosts_target(self):
        # Keep behavior close to Paramiko AutoAddPolicy() by disabling host key
        # verification when strict checking is not requested.
        return 'NUL' if os.name == 'nt' else '/dev/null'

    def build_ssh_command(self, tracker_cli, sshtimeout=5):
        target = self.tracker_ip
        if self.tracker_user:
            target = self.tracker_user + '@' + self.tracker_ip

        ssh_cmd = [
            self.sshbin,
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=' + str(sshtimeout),
            '-p', str(self.tracker_port),
        ]

        if not self.strict_host_key_checking:
            ssh_cmd.extend([
                '-o', 'StrictHostKeyChecking=accept-new',
            ])

        if self.tracker_keyfile:
            ssh_cmd.extend(['-i', self.tracker_keyfile])

        ssh_cmd.append(target)
        ssh_cmd.append(tracker_cli)
        return ssh_cmd

    def ssh_connect(self):
        Domoticz.Debug(self.tracker_ip + ' ====> SSH start connect on port ' + str(self.tracker_port))

        # The subprocess/OpenSSH backend intentionally supports only non-interactive
        # authentication methods. Password-based authentication would either block
        # on a prompt or require an unsafe helper such as sshpass.
        if self.tracker_password:
            Domoticz.Error(
                self.tracker_ip
                + ' ====> SSH password authentication is not supported by subprocess backend'
            )
            self.connected = False
            return False

        if self.tracker_keyfile:
            Domoticz.Debug(self.tracker_ip + ' ====> SSH using key: ' + str(self.tracker_keyfile))
        else:
            Domoticz.Debug(
                self.tracker_ip + ' ====> SSH using OS-level key/default ssh configuration'
            )

        # No persistent SSH session is established here. A new ssh process is started
        # for each poll. Mark configuration as ready.
        Domoticz.Status(self.tracker_ip + ' ====> SSH subprocess backend ready')
        self.connected = True
        return True

    def getfromssh(self, tracker_cli, alltimeout=5, sshtimeout=3):
        Domoticz.Debug(self.tracker_ip + ' ====> SSH Fetching data using: ' + tracker_cli)
        starttime = datetime.now()

        if not self.connected:
            Domoticz.Debug(self.tracker_ip + ' ====> SSH not connected ... connecting')
            if not self.ssh_connect():
                return False, ''

        ssh_cmd = self.build_ssh_command(tracker_cli, sshtimeout)

        try:
            Domoticz.Debug(
                self.tracker_ip
                + ' ====> SSH command: '
                + ' '.join(shlex.quote(arg) for arg in ssh_cmd)
            )

            proc = subprocess.run(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=alltimeout,
                check=False,
            )

            ssh_output = proc.stdout
            ssh_error = proc.stderr

            if proc.returncode != 0:
                Domoticz.Error(
                    self.tracker_ip
                    + ' ====> SSH returned rc '
                    + str(proc.returncode)
                    + ': '
                    + ssh_error.strip()
                )
                self.connected = False
                return False, ''

            if ssh_error:
                Domoticz.Error(self.tracker_ip + ' ====> SSH returned error:' + ssh_error)

            Domoticz.Debug(self.tracker_ip + ' ====> SSH returned (decoded):' + ssh_output)

        except subprocess.TimeoutExpired:
            Domoticz.Error(
                self.tracker_ip + ' ====> SSH failed with exception: command timed out'
            )
            self.connected = False
            return False, ''
        except FileNotFoundError:
            Domoticz.Error(
                self.tracker_ip
                + ' ====> SSH failed with exception: ssh binary not found: '
                + str(self.sshbin)
            )
            self.connected = False
            return False, ''
        except Exception as e:
            Domoticz.Error(self.tracker_ip + ' ====> SSH failed with exception: ' + str(e))
            self.connected = False
            return False, ''

        timespend = datetime.now() - starttime
        Domoticz.Debug(
            self.tracker_ip
            + ' ====> SSH session took '
            + str(timespend.microseconds // 1000)
            + ' milliseconds.'
        )
        return True, ssh_output

    def stop_now(self):
        self.is_ready = False
        self.connected = False
        Domoticz.Debug(self.tracker_ip + ' ====> SSH subprocess backend stopped')
        super().stop_now()
