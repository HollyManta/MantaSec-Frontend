import re
import MySQLdb

import db_functions

def getAggregationList():
    cur, db = db_functions.getCursorDB()

    cur.execute("SELECT regex,name FROM aggregationRules")
    aggregationList = cur.fetchall()
    db.close()

    return aggregationList


## TODO - what does the function do and what are the expected inputs?
## Intent: Take a list of vulns and group similar vulns together, e.g. all SSL vulns become one
## "insecure SSL" issue. vulnList is a list containing the common vuln-data structure.
## TODO consider replacing the list data structures with JSON
def aggregate(vulnList):

    ## TODO - put this into the database
    #aggregateRuleList = [
    #                        # Example: KB4516115: Security update for Adobe Flash Player (September 2019)
    #                        {"regex":"^KB\d{7}:.*$","name":"Missing Microsoft KB Update"},
    #                        {"regex":"SSL Self-Signed Certificate","name":"Insecure X.509 Certificate"},
    #                        {"regex":"SSL Certificate Chain Contains Certificates Expiring Soon","name":"Insecure X.509 Certificate"},
    #                        {"regex":"SSL Certificate Signed Using Weak Hashing Algorithm \(Known CA\)","name":"Insecure X.509 Certificate"},
    #                        {"regex":"SSL Medium Strength Cipher Suites Supported \(SWEET32\)","name":"Insecure SSL/TLS Ciphers"},
    #                        {"regex":"SSL Cipher Block Chaining Cipher Suites Supported","name":"Insecure SSL/TLS Ciphers"},
    #                        {"regex":"TLS Version 1.0 Protocol Detection","name":"Insecure SSL/TLS Ciphers"},
    #                        {"regex":"TLS Version 1.1 Protocol Detection","name":"Insecure SSL/TLS Ciphers"}
    #                    ]

    aggregateRuleList = getAggregationList()
    aggregatedList = []

    ## Iterate over the upcoming vulnerability data and check if they match an aggregation rule
    for vuln in vulnList:
        ## The default is not-matched until a match is found
        aggregated = False

        ## [For each vunerability] iterate over each aggregation rule and flag for aggregation if matched
        for aggregateRule in aggregateRuleList:
                ## Check the regex against the name and aggregate if they match
                if(re.match(aggregateRule["regex"], vuln["name"])):
                    ## Check if the aggregate-vuln exists and if not create it
                    if not any(d['name'] == aggregateRule["name"] for d in aggregatedList):
                        aggregated = True
                        aggregatedList.append( {
                                                "name" : aggregateRule["name"],
                                                "affected" : vuln["affected"], 
                                                "description" : [ { 
                                                                    "name" : vuln["name"],
                                                                    "affected" : vuln["affected"],
                                                                    "description" : vuln["description"],
                                                                    "risk" : vuln["risk"] 
                                                                } ], 
                                                "risk" : "Aggregated"
                                            } )
                    ## else, this entry must already exist check if the host:port is already in the list
                    ## and if it's not then append it to the vuln list held in description
                    else:
                        ## iterate over the aggregate list until we find the entry we want to update
                        for aggregate in aggregatedList:
                            ##  we've found the right entry so add to the "description" list
                            ## TODO - we're storing sub-vulns in "description, this is probably not-obvious
                            if aggregate["name"] == aggregateRule["name"]:
                                aggregated = True
                                aggregate["description"].append( { 
                                                                    "name" : vuln["name"], 
                                                                    "affected" : vuln["affected"], 
                                                                    "description" : vuln["description"],
                                                                    "risk" : vuln["risk"] 
                                                                }  )
                                ## Check, one at a time, if the host:port is new, if it is add it to the list
                                for hostPort in vuln["affected"]:
                                    if hostPort not in aggregate["affected"]:
                                        aggregate["affected"].append( hostPort )
                    break # We matched a rule so stop looking
        if not aggregated:
            aggregatedList.append(vuln)

    return aggregatedList


if __name__ == "__main__":
    pass
## TODO - Write tests here
    #aggregatedOutput = aggregate()
    #print(aggregatedOutput)

    ## TODO - implement args to load a nessus file and test the parser
    ## TODO - implement args to load two nessus files and test the merger
    #import argparse

    #parser = argparse.ArgumentParser()
    #parser.add_argument("inputFile", help="A Nessus file to parse")
    #args = parser.parse_args()
    
    #with open(args.inputFile,'r') as inputFile:
    #    inputData = inputFile.read()

    #if (check(inputData) > 0):
    #    parsed = parse(inputData)
    #    print(parsed)
    #else:
    #    print("Error: not a nessus file :(")