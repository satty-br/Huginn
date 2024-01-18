class Secret:
    def __init__(self, description, start_line, end_line, start_column, end_column, match, secret, file, symlink_file, commit, entropy, author, email, date, message, tags, rule_id, fingerprint):
        self.description = description
        self.start_line = start_line
        self.end_line = end_line
        self.start_column = start_column
        self.end_column = end_column
        self.match = match
        self.secret = secret
        self.file = file
        self.symlink_file = symlink_file
        self.commit = commit
        self.entropy = entropy
        self.author = author
        self.email = email
        self.date = date
        self.message = message
        self.tags = tags
        self.rule_id = rule_id
        self.fingerprint = fingerprint
        self.valid = None
