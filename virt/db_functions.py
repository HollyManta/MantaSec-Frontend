import MySQLdb
import os

## TODO - is this inefficient? Is it better to pass around a cursort variable?
def getCursorDB():
    ## Pull credentials from the environment variables
    DATABASE = {
        'NAME': os.environ['RDS_DB_NAME'],
        'USER': os.environ['RDS_USERNAME'],
        'PASSWORD': os.environ['RDS_PASSWORD'],
        'HOST': os.environ['RDS_HOSTNAME'],
        'PORT': int(os.environ['RDS_PORT'])
    }

    ## Connect to the DB but don't specify a database name, incase we need to initiate it
    db = MySQLdb.connect(   host=DATABASE["HOST"],
                            user=DATABASE["USER"],
                            passwd=DATABASE["PASSWORD"],
                            port=DATABASE["PORT"],
                            db="frontend"
                        )

    cur = db.cursor(MySQLdb.cursors.DictCursor)
        
    return cur, db

## Cur is a database cursor to the connected DB
def init():
    DATABASE = {
        'NAME': os.environ['RDS_DB_NAME'],
        'USER': os.environ['RDS_USERNAME'],
        'PASSWORD': os.environ['RDS_PASSWORD'],
        'HOST': os.environ['RDS_HOSTNAME'],
        'PORT': int(os.environ['RDS_PORT'])
    }

    ## Connect to the DB but don't specify a database name, incase we need to initiate it
    db = MySQLdb.connect(   host=DATABASE["HOST"],
                            user=DATABASE["USER"],
                            passwd=DATABASE["PASSWORD"],
                            port=DATABASE["PORT"],
                        )

    cur = db.cursor()

    ## Temporary whilst developing the schema; clear the DB each time and rebuild it
    

    ## Check if the DB exits, if not create it
    cur.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'frontend'")
    if len(cur.fetchall()) != 0:
        cur.execute("DROP DATABASE frontend")

    
    cur.execute("CREATE DATABASE frontend")
    cur.execute("USE frontend")
    #cur.execute("CREATE TABLE users (email VARCHAR(256), hash VARCHAR(64), firstName VARCHAR(256), lastName VARCHAR(256))")

    cur.execute("CREATE TABLE aggregationRules (id INT, regex VARCHAR(256), name VARCHAR(256))")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (1, '^KB\d{7}:.*$','Missing Microsoft KB Update')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (2, 'SSL Self-Signed Certificate', 'Insecure X.509 Certificate')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (3, 'SSL Certificate Chain Contains Certificates Expiring Soon', 'Insecure X.509 Certificate')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (4, 'SSL Certificate Signed Using Weak Hashing Algorithm \(Known CA\)','Insecure SSL/TLS Ciphers')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (5, 'SSL Medium Strength Cipher Suites Supported \(SWEET32\)','Insecure SSL/TLS Ciphers')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (6, 'SSL Cipher Block Chaining Cipher Suites Supported','Insecure SSL/TLS Ciphers')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (7, 'TLS Version 1.0 Protocol Detection','Insecure SSL/TLS Ciphers')")
    cur.execute("INSERT INTO aggregationRules (id, regex, name) VALUES (8, 'TLS Version 1.1 Protocol Detection','Insecure SSL/TLS Ciphers')")

    db.commit()
    db.close()
    
    print("DB set up done I guess")
