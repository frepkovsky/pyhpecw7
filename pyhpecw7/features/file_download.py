"""Manage file transfer to HPCOM7 devices.
"""
from scp import SCPClient
from lxml import etree
from pyhpecw7.utils.xml.lib import *
from pyhpecw7.features.errors import FileTransferUnsupportedProtocol, FileTransferError, FileHashMismatchError

import paramiko
import hashlib
import os

class FileUpload(object):
    """This class is used to download file from ``HPCOM7`` device.

    Note:
        SCP or SFTP should first be enabled on the device.

    Note:
        When using this class, the passed in ``HPCOM7`` object should
        be constructed with the ``timeout`` equal to at least 60 seconds.
        Remote MD5 sum calculations can take some time.

    Args:
        device (HPCOM7): connected instance of
            a ``pyhpecw7.comware.HPCOM7`` object.
        proto (str): file transfer protocol - 'scp' or 'sftp'.
        src (str): - Full path or filename of remote file to be downloaded.
            If just a filename is supplied, 'flash:/' will be prepended.
            If nothing is supplied, the source filename will be used,
            and 'flash:/' will be prepended.
        dst (str): OPTIONAL - Full path to local file where remote file is
            saved to. If not specified it is saved to current dir.
        port (int): OPTIONAL - The SSH port over which
            the SCP connection is made. Defaults to 22.

    Attributes:
        device (HPCOM7): connected instance of
            a ``pyhpecw7.comware.HPCOM7`` object.
        src (str): Full path to remote file to be copied.
        dst (str): Full path of local file.
        port (int): The SSH port over which
            the SCP connection is made.
        remote_dir_exists (bool): Whether there remote
            directory exists.
    """
    def __init__(self, device, proto, src, dst=None, port=22):
        self.device = device
        self.proto = proto
        self.src = src

        if self.src.find(':/') < 0:
            self._remote_dir = 'flash:/'
            self.src = self._remote_dir + self.src
        else:
            self._remote_dir = '/'.join(
                self.src.split('/')[:-1]) + '/'

        if not dst:
            self.dst = os.path.basename(src)
        else:
            self.dst = dst

        self.port = port

        print(str(self.proto) + " transfer")
        print("src: " + str(self.src))
        print("dst: " + str(self.dst))

    def _get_remote_md5(self):
        """Return the md5 sum of the remote file,
        if it exists.
        """
        E = action_element_maker()
        top = E.top(
            E.FileSystem(
                E.Files(
                    E.File(
                        E.SrcName(self.src),
                        E.Operations(
                            E.md5sum()
                        )
                    )
                )
            )
        )


        nc_get_reply = self.device.action(top)
        reply_ele = etree.fromstring(nc_get_reply.xml)
        md5sum = find_in_action('md5sum', reply_ele)

        if md5sum is not None:
            return md5sum.text.strip()

    def _get_local_md5(self, blocksize=2**20):
        """Get the md5 sum of the local file,
        if it exists.
        """
        m = hashlib.md5()
        with open(self.dst, "rb") as f:
            buf = f.read(blocksize)
            while buf:
                m.update(buf)
                buf = f.read(blocksize)
        return m.hexdigest()


    def transfer_file(self, hostname=None, username=None, password=None, allow_agent=False, look_for_keys=False, ssh_config=None):
        """Transfer the file to the remote device over SCP.

        Note:
            If any arguments are omitted, the corresponding attributes
            of the ``self.device`` will be used.

        Args:
            hostname (str): OPTIONAL - The name or
                IP address of the remote device.
            proto (str): OPTIONAL - Protocol to be used
                for transfer - 'scp' or 'sftp'
            username (str): OPTIONAL - The SSH username
                for the remote device.
            password (str): OPTIONAL - The SSH password
                for the remote device.

        Raises:
            FileTransferError: if an error occurs during the file transfer.
            FileHashMismatchError: if the source and
                destination hashes don't match.
            FileNotReadableError: if the local file doesn't exist or isn't readable.
            FileNotEnoughSpaceError: if there isn't enough space on the device.
            FileRemoteDirDoesNotExist: if the remote directory doesn't exist.
        """

        hostname = hostname or self.device.host
        username = username or self.device.username
        password = password or self.device.password
        ssh_config = ssh_config or self.device.ssh_config
        key_filename = None

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if ssh_config is not None:
            sshconfig = paramiko.SSHConfig()
            sshconfig.parse(open(ssh_config))
            cfg=sshconfig.lookup('dev')
            key_filename=cfg['identityfile'][0]

        ssh.connect(
            hostname=hostname,
            username=username,
            password=password,
            port=self.port,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
            key_filename=key_filename)

        if self.proto == "scp":
            scp = SCPClient(ssh.get_transport())
            try:
                scp.get(self.src, self.dst)
            except:
                raise FileTransferError
            scp.close()
        elif self.proto == "sftp":
            sftp = ssh.open_sftp()
            sftp.sshclient = ssh
            try:
                sftp.get(self.src.strip('flash:'), self.dst)
            except:
                raise FileTransferError
            sftp.close()
        else:
            raise FileTransferUnsupportedProtocol(self.proto)


        src_hash = self._get_local_md5()
        dst_hash = self._get_remote_md5()

        if src_hash != dst_hash:
            raise FileHashMismatchError(self.src, self.dst, src_hash, dst_hash)
