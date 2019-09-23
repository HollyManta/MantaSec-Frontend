from xml.etree import ElementTree as ET

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

    return 0

def parse(nessusData):
    vulnerabilities = []

    # Check that we have a valid XML file
    error = check(nessusData)
    if error != 0:
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
                    vulnName    = item.find('plugin_name').text
                    description = item.find('description').text
                    vulnPort    = item.attrib['port']
                    riskRating  = item.find('risk_factor').text
                    hostPost = currentHost + ":" + vulnPort

                    if not any(d['name'] == vulnName for d in vulnerabilities):    
                        vulnerabilities.append( {"name" : vulnName, "affected" : [ hostPost], "description" : description, "risk" : riskRating } )    # TODO - can we use JSON directly instead of this?
                    else:
                        for vuln in vulnerabilities:
                            if vuln["name"] == vulnName:
                                if hostPost not in vuln["affected"]:
                                    vuln["affected"].append( hostPost )

    return vulnerabilities

def merge(vulnlist, nessusData):
    # TODO refactor this "newvulns" and "oldvulns" makes it difficult to follow the code
    newVulns = parse(nessusData)

    for vuln in newVulns:
        if not any(d['name'] == vuln["name"] for d in vulnlist):
            vulnlist.append( {"name" : vuln["name"], "affected" : vuln["affected"], "description" : "", "risk" : vuln["risk"] } )    # TODO - can we use JSON directly instead of this?
        else:
            for oldvuln in vulnlist:
                if oldvuln["name"] == vuln["name"]:
                    for host in vuln["affected"]:
                        if host not in oldvuln["affected"]:
                            oldvuln["affected"].append( host )
    
    return vulnlist



if __name__ == "__main__":
    with open('C:\\Users\\Holly\\Downloads\\LocalScan-172-20-10_o0iv5u.nessus','r') as inputFile:
        content = inputFile.read()

    data = parse(content)
    if isinstance(data, int):
        print("Fatal error occured.")
    else:
        print(data)

    

            