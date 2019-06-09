

def perm_check(checkSet, mainSet):
    checkSet = set(checkSet)
    mainSet = set(mainSet)
    if checkSet.issubset(mainSet):
        return True
    else:
        return False

def is_subset(checkSet, mainSet):
    checkSet = set(checkSet)
    mainSet = set(mainSet)
    if checkSet.issubset(mainSet):
        return True
    else:
        return False
