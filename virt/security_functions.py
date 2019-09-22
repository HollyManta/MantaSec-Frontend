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
