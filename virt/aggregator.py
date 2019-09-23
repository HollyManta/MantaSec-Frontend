import re

def aggregate(vulnList):
    #aggregateMe = {
    #            "SSL Self-Signed Certificate":"Insecure X.509 Certificate",
    #            "SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)": "Insecure X.509 Certificate",
    #            "SSL Medium Strength Cipher Suites Supported (SWEET32)":"Insecure SSL/TLS Ciphers",
    #            "SSL Cipher Block Chaining Cipher Suites Supported": "Insecure SSL/TLS Ciphers",
    #            "TLS Version 1.0 Protocol Detection": "Insecure SSL/TLS Ciphers"
    #            }

    aggregateRuleList = [
                            #KB4516115: Security update for Adobe Flash Player (September 2019)
                            {"regex":"^KB\d{7}:.*$","name":"Missing Microsoft KB Update"},
                            {"regex":"SSL Self-Signed Certificate","name":"Insecure X.509 Certificate"},
                            {"regex":"SSL Certificate Chain Contains Certificates Expiring Soon","name":"Insecure X.509 Certificate"},
                            {"regex":"SSL Certificate Signed Using Weak Hashing Algorithm \(Known CA\)","name":"Insecure X.509 Certificate"},
                            {"regex":"SSL Medium Strength Cipher Suites Supported \(SWEET32\)","name":"Insecure SSL/TLS Ciphers"},
                            {"regex":"SSL Cipher Block Chaining Cipher Suites Supported","name":"Insecure SSL/TLS Ciphers"},
                            {"regex":"TLS Version 1.0 Protocol Detection","name":"Insecure SSL/TLS Ciphers"},
                            {"regex":"TLS Version 1.1 Protocol Detection","name":"Insecure SSL/TLS Ciphers"}
                        ]

    aggregatedList = []

    for vuln in vulnList:
        aggregated = False
        for aggregateRule in aggregateRuleList:
            if re.match(aggregateRule["regex"], vuln["name"]) is not None:
                aggregated = True
                print("Match: " + vuln["name"])
                #if not any(d['name'] == aggregateMe[vuln["name"]] for d in aggregatedList):
                if not any(d['name'] == aggregateRule["name"] for d in aggregatedList):
                    aggregatedList.append( {"name" : aggregateRule["name"], "affected" : vuln["affected"], "description" : [ { "name" : vuln["name"], "affected" : vuln["affected"], "description" : vuln["description"], "risk" : vuln["risk"] } ], "risk" : "Aggregated" } )
                    #print(vuln["name"] + " becoming " + aggregateMe[vuln["name"]])
                else:
                    #print("Need to append to an aggregate")
                    for aggregate in aggregatedList:
                        if aggregate["name"] == aggregateRule["name"]:
                            #print(vuln["name"] + " is being added to " + aggregate["name"]) 
                            aggregate["description"].append( { "name" : vuln["name"], "affected" : vuln["affected"], "description" : vuln["description"], "risk" : vuln["risk"] }  )
                            for hostPort in vuln["affected"]:
                                if hostPort not in aggregate["affected"]:
                                    aggregate["affected"].append( hostPort )
        if not aggregated:
            aggregatedList.append(vuln)

    
    #for vuln in vulnList:
    #    if vuln["name"] in aggregateMe:
    #        if not any(d['name'] == aggregateMe[vuln["name"]] for d in aggregatedList):
    #            aggregatedList.append( {"name" : aggregateMe[vuln["name"]], "affected" : vuln["affected"], "description" : [ { "name" : vuln["name"], "affected" : vuln["affected"], "description" : vuln["description"], "risk" : vuln["risk"] } ], "risk" : "Aggregated" } )
    #            #print(vuln["name"] + " becoming " + aggregateMe[vuln["name"]])
    #        else:
    #            #print("Need to append to an aggregate")
    #            for aggregate in aggregatedList:
    #                if aggregate["name"] == aggregateMe[vuln["name"]]:
    #                    #print(vuln["name"] + " is being added to " + aggregate["name"]) 
    #                    aggregate["description"].append( { "name" : vuln["name"], "affected" : vuln["affected"], "description" : vuln["description"], "risk" : vuln["risk"] }  )
    #                    for hostPort in vuln["affected"]:
    #                        if hostPort not in aggregate["affected"]:
    #                            aggregate["affected"].append( hostPort )
    #    else:
    #        aggregatedList.append(vuln)

    return aggregatedList