#Overloaded charAt operator on a given string
def char(string, b):
    if b < len(string):
        return string[b]
    else:
        return None