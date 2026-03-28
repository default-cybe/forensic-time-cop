class BaseRule:
    """
    Every detection rule inherits from this.
    Each rule must implement the `analyze` method.
    """
    name = "Base Rule"
    description = ""
    score = 0  # How much this rule contributes to suspicion score

    def analyze(self, data):
        """
        Takes in parsed artifact data.
        Returns a list of findings (empty list = nothing detected).
        Each finding is a dict with keys: file, reason, score
        """
        raise NotImplementedError("Each rule must implement analyze()")