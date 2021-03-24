class service:
    def __init__(self, name, user, pwd, note):
        self.name = name
        self.user = user
        self.pwd = pwd
        self.note = note

    def setName(self, name):
        self.name = name

    def getName(self):
        return self.name

    def setUser(self, user):
        self.user = user

    def getUser(self):
        return self.user

    def setPwd(self, pwd):
        self.pwd = pwd

    def getPwd(self):
        return self.pwd

    def setNote(self, note):
        self.note = note

    def getNote(self):
        return self.note

