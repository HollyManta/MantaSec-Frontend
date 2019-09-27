import re

def cleanRisk(risk):
    # To prevent attack payloads in risk rating from scanner
    if risk == "Critical":
        return "critical"
    elif risk == "High":
        return "high"
    elif risk == "Medium":
        return "medium"
    elif risk == "Low":
        return "low"
    elif risk == "None":
        return "info"
    else:
        return "white" # Highlights the issue as having unknown risk

def entityEncode(inputText):
    inputText = inputText.replace("'","&apos;")
    inputText = inputText.replace("\"","&quot;")
    inputText = inputText.replace("<","&lt;")
    inputText = inputText.replace(">","&gt;")
    inputText = inputText.replace("{","&#x007B;")
    inputText = inputText.replace("}","&#x007D;")
    return inputText

def passStrongEnough(password):
    longEnough = len() >= 10                    # Returns true if long enough
    hasUppers = re.match("/[A-Z]/", password)   # Returns true which eq 1
    hasLowers = re.match("/[a-z]/", password)   # Returns true which eq 1
    hasNumbers = re.match("/\d/", password)     # Returns true which eq 1
    hasSymbols = re.match("/\W/", password)     # Returns true which eq 1

    ## The password must be >= 10 long and contain three of four complexity items
    if (longEnough and hasUppers + hasLowers + hasNumbers + hasSymbols >= 3):
        return true
    else:
        return false