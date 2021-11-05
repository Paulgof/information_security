class VerbosePrint:

    def __init__(self, verbose=False):
        self.verbose = verbose

    def __call__(self, *args, **kwargs):
        self.print(*args, **kwargs)

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)
