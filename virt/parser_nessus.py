from xml.etree import ElementTree as ET

## TODO - what does the function do and what are the expected inputs?
def check(nessusData):
    try:
        root = ET.fromstring(nessusData)
    except ET.ParseError:
        print("Error: Expected a .Nessus file. Could not parse file.") # Somehow log this?
        return -1
    except:
        return -2 # This should never happen so needs to be logged to disk

    if root.tag != 'NessusClientData_v2':
        print("Error: expected 'NessusClientData_v2'") # Somehow log this?
        return -3

    if root[0].tag != "Policy" or root[1].tag != "Report":
        print("Error: Could not parse policy/report content.'") # Somehow log this?
        return -4

    return True

## TODO - what does the function do and what are the expected inputs?
def parse(nessusData):
    vulnerabilities = []

    # Check that we have a valid XML file
    error = check(nessusData)
    if error < 0:
        return error
        
    root = ET.fromstring(nessusData)
    for host in root[1]:
        if host.tag != "ReportHost":
            print("Unparsed host?") # Shouldn't happen, but catch it if it does
            return -5
        else:
            # TODO How to deal with scanners which swap between host, IP, and FQDN?
            currentHost = host.attrib['name']
            for item in host:
                if item.tag == "ReportItem": # This skips HostProperties
                    pluginID = "nessus_" + item.attrib['pluginID']
                    vulnName    = item.find('plugin_name').text
                    description = item.find('description').text
                    vulnPort    = item.attrib['port']
                    riskRating  = item.find('risk_factor').text
                    hostPost = currentHost + ":" + vulnPort

                    if not any(d['name'] == vulnName for d in vulnerabilities):    
                        vulnerabilities.append( {"name" : vulnName, "affected" : [ hostPost], "description" : description, "risk" : riskRating, "plugin" : pluginID } )    # TODO - can we use JSON directly instead of this?
                    else:
                        for vuln in vulnerabilities:
                            if vuln["name"] == vulnName:
                                if hostPost not in vuln["affected"]:
                                    vuln["affected"].append( hostPost )

    return vulnerabilities

## TODO - what does the function do and what are the expected inputs?
def merge(vulnlist, nessusData):
    ## TODO refactor this "newvulns" and "oldvulns" makes it difficult to follow the code
    newVulns = parse(nessusData)

    for vuln in newVulns:
        if not any(d['name'] == vuln["name"] for d in vulnlist):
            ## TODO - remove plugin description and load it from the DB
            vulnlist.append( {"name" : vuln["name"], "affected" : vuln["affected"], "description" : "", "risk" : vuln["risk"], "plugin" : vuln["plugin"] } )    # TODO - can we use JSON directly instead of this?
        else:
            for oldvuln in vulnlist:
                if oldvuln["name"] == vuln["name"]:
                    for host in vuln["affected"]:
                        if host not in oldvuln["affected"]:
                            oldvuln["affected"].append( host )
    
    return vulnlist



if __name__ == "__main__":
    ## TODO - implement args to load a nessus file and test the parser
    ## TODO - implement args to load two nessus files and test the merger
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("inputFile", help="A Nessus file to parse")
    args = parser.parse_args()
    
    with open(args.inputFile,'r') as inputFile:
        inputData = inputFile.read()

    if (check(inputData) > 0):
        parsed = parse(inputData)
        print(parsed)
    else:
        print("Error: not a nessus file :(")
