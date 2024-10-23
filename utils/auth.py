import re
def auth_password(password):
    if(len(password) < 8):
        return False
    elif not re.search(r"[A-Z]",password):
        return False
    elif not re.search(r"[a-z]", password):
        return False
    elif not re.search(r"[0-9]", password):
        return False
    elif not re.search(r"[^a-zA-Z0-9]", password):
        return False
    return True
    