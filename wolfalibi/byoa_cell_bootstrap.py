"""Trusted in-cell adapter for the operator-selected, restricted Python entrypoint.

The supervisor embeds this module in the measured command line. The inherited
Solitary worker configures limits and seccomp, then asks the broker for the
fixed public fixture. Only its measured, owner-authorized reply starts the agent.
"""


class SubmittedAgent:
    def __init__(self, probe, source, fixture_sha256):
        self.probe = probe
        self.source = source
        self.fixture_sha256 = fixture_sha256

    def wrap(self, broker_read, *, surface, operation):
        import hashlib

        def after_release(channel, request):
            data = broker_read(channel, request)
            if data is None or hashlib.sha256(data).hexdigest() != self.fixture_sha256:
                raise ValueError("the expected synthetic fixture did not arrive")
            # The source has been strictly checked and captured by the manifest
            # loader. Compilation and the first execution both occur after this
            # one-use reply. Neither channel nor the broker callback is exposed.
            globals_ = {"__builtins__": {}}
            code = compile(self.source.decode("ascii"), "<approved-agent>", "exec", dont_inherit=True)
            exec(code, globals_)
            read_fixture = self.probe.wrap(lambda: data, surface=surface, operation=operation)
            decision = globals_["run"]({"read_fixture": read_fixture})
            if decision is not True and not (type(decision) is bytes and decision == data):
                raise ValueError("the approved agent did not accept the fixture")
            summary = self.probe.summary()
            if summary["events"] != 1 or summary["counts"] != {"filesystem.read.success": 1}:
                raise ValueError("the agent did not complete exactly one declared callback")
            return data

        return after_release

    def close(self):
        self.probe.close()

    def summary(self):
        return self.probe.summary()
