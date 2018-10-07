import mailpile.platforms


class SandboxBase(object):
    sandbox_binary = ''

    def __init__(self, binary, restrictions=list()):
        self.binary = binary
        self.restrictions = restrictions

    @classmethod
    def available(cls):
        return mailpile.platforms.DetectBinaries(which=cls.sandbox_binary) is not None

    def _build_args(self):
        if self.binary:
            return [self.binary]

        return []

    def _build_switches(self):
        return []

    def cmd(self):
        sandbox_path = mailpile.platforms.DetectBinaries(which=self.sandbox_binary)

        if not sandbox_path:
            return [self.binary]

        cmd = [sandbox_path]
        cmd.extend(self._build_switches())
        cmd.extend(self._build_args())
        return cmd

    def __str__(self):
        return ' '.join(self.cmd())


class Firejail(SandboxBase):
    RESTRICT_NETWORK = 'network'
    RESTRICT_DEVICES = 'devices'
    RESTRICT_FILE_WRITE = 'readonly_fs'

    sandbox_binary = 'Firejail'

    def __init__(self, binary, restrictions=None):
        if not restrictions:
            restrictions = [self.RESTRICT_NETWORK, self.RESTRICT_DEVICES]

        super(Firejail, self).__init__(binary, restrictions=restrictions)

    def _build_switches(self):
        kwargs = {'quiet': None,
                'noroot': None,
                'nonewprivs': None,
                'caps.drop': 'all',
                'x11': 'none',
                'nosound': None,
                'no3d': None}

        if self.RESTRICT_NETWORK in self.restrictions:
            kwargs['net'] = 'none'

        if self.RESTRICT_FILE_WRITE in self.restrictions:
            # Note that user home remains writeable due to firejail
            # defaults.
            kwargs['read-only'] = '~'

        if self.RESTRICT_DEVICES in self.restrictions:
            kwargs['private-dev'] = None

        for key, val in kwargs.iteritems():
            if val:
                yield '--%s=%s' % (key, val)
            else:
                yield '--%s' % key

SANDBOXES = [Firejail]

def get_sandbox():
    for sandbox in SANDBOXES:
        if sandbox.available():
            return sandbox

Sandbox = get_sandbox()
