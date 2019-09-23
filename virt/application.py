from flask import Flask, request, render_template, Markup, make_response, redirect
import os
import MySQLdb
import bcrypt
import re

import template_parts
import security_headers
import parser_nessus
import vulnerability_handling
import aggregator


application = Flask(__name__)

   
DATABASE = {
    'NAME': os.environ['RDS_DB_NAME'],
    'USER': os.environ['RDS_USERNAME'],
    'PASSWORD': os.environ['RDS_PASSWORD'],
    'HOST': os.environ['RDS_HOSTNAME'],
    'PORT': int(os.environ['RDS_PORT'])
}

# Connect without DB incase we're a fresh instance and need to initiate
db = MySQLdb.connect(   host=DATABASE["HOST"],
                        user=DATABASE["USER"],
                        passwd=DATABASE["PASSWORD"],
                        port=DATABASE["PORT"]
                    )

cur = db.cursor()
cur.execute("DROP DATABASE frontend")
cur.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'frontend'")
if len(cur.fetchall()) == 0:
    print("No database")
    cur.execute("CREATE DATABASE frontend")
    cur.execute("use frontend")
    cur.execute("CREATE TABLE users (email VARCHAR(256), hash VARCHAR(64), firstName VARCHAR(256), lastName VARCHAR(256))")
else:
    cur.execute("USE frontend")

#password = b"test password here"
#hashed = bcrypt.hashpw(password, bcrypt.gensalt())

#if bcrypt.checkpw(password, hashed):
#    print("It Matches!")
#else:
#    print("It Does not Match :(")

# Set up the template parts
sidebar = Markup(template_parts.sidebar)
navbar = Markup(template_parts.navbar)
headercontent = Markup(template_parts.headercontent)

@application.route('/')
@application.route('/index')
def show_index():
    renderedTemplate = render_template("index.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response

@application.route('/db-create')
def show_db():
    output = "DB Status: " + DATABASE["NAME"]
    return output

@application.route('/upload', methods=['GET','POST'])
def show_upload(): 
    if request.method == 'POST':
        files = request.files.getlist('file[]')
        vulns = []
        for file in files:
            inputData = file.read()
            if parser_nessus.check(inputData) == 0:
                if len(vulns) == 0:
                    vulns = parser_nessus.parse(inputData)  # First file we can parse, so we're starting fresh
                else:
                    vulns = parser_nessus.merge(vulns, inputData)   # Already got some vulns, so merge the results
            else:
                print("Unsupported file type") 
                   
        vulns = aggregator.aggregate(vulns)
        vulnlist = vulnerability_handling.orderVulns(vulns)
        vulnlist = Markup(vulnlist)

        renderedTemplate = render_template("lazy-scan.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, vulndata = vulnlist)
        response = make_response(renderedTemplate)
        response = security_headers.add(response)
        return response 

    renderedTemplate = render_template("upload.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response
    
@application.route('/login')
def show_login():
    renderedTemplate = render_template("login.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response

@application.route('/register', methods=['GET','POST'])
def show_register(): 
    if request.method == 'POST':
        # Process registration here
        # Check that we received each parameter (email, password, confirm)
        paramList = request.form.to_dict().keys()
        if not ("email" in paramList and "password" in paramList and "confirm" in paramList):
            registrationErrors = "Error: Missing parameter!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)

        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        #Check if password and confirm match
        if (confirm != password):
            registrationErrors = "Error: Invalid email address!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)

        #Check password complexity

        # Check the email address is valid
        regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
        if not (re.search(regex,email)): 
            registrationErrors = "Error: Invalid email address!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)
        
        # Check the email is not in use
        

        # If registration fails then contnue to load the template with the original email address
        #return redirect("/profile", code=302)
    renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response

@application.route('/profile')
def show_profile():
    renderedTemplate = render_template("profile.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response

#@application.route('/dashboard')
#def show_dashboard():
#    renderedTemplate = render_template("dashboard.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
#    response = make_response(renderedTemplate)
#    response = security_headers.add(response)
#    return response

#@application.route('/vulns')
#def show_vulns():
    ## TODO DRAGONS
    ## This code may be vulnerable to template injection
    ## This is also likely vulnerable to cross-site scripting
#    vulns = [   
#                ['SQL Injection', 'high', 'Description here', '10.1.1.1, 10.1.1.1'],
#                ['Arbitrary File Upload', 'high',  'Another description', '10.1.1.2, 10.1.1.3'],
#                ['Cross-site Scripting', 'medium', 'Data here', '10.1.1.4'],
#                ['Information Disclosure: Server Header','low', 'An explanation', '10.1.1.6'],
#                ['Missing HTTP Security Headers', 'low', 'Please explain', '10.1.1.2'],
#                ['CAA Not Implemented', 'low', 'Info for you', '10.1.1.6']
#            ]
    
#    vulnlist = ""

#    for vuln in vulns:
#        vulnlist = vulnlist + '<div class="row">'
#        vulnlist = vulnlist + '<div class="widget-one">'
#        vulnlist = vulnlist + '<div class="widget vuln-' + vuln[1] + '-widget">'
#        vulnlist = vulnlist + '<h3 class="">' + vuln[0] + '</h3>'
#        vulnlist = vulnlist + '<p class="vuln-desc">' + vuln[2] + '</p>'
#        vulnlist = vulnlist + '<p class="vuln-hosts"><b>Affected hosts:</b> ' + vuln[3] + '</p>'
#        vulnlist = vulnlist + '</div>'
#        vulnlist = vulnlist + '</div>'
#        vulnlist = vulnlist + '</div>'

#    vulnlist = Markup(vulnlist)

#    renderedTemplate = render_template("vulns.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, vulnlist = vulnlist)
#    response = make_response(renderedTemplate)
#    response = security_headers.add(response)
#    return response

#@application.route('/scans')
#def show_scans():
#    renderedTemplate = render_template("scans.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
#    response = make_response(renderedTemplate)
#    response = security_headers.add(response)
#    return response

#@application.route('/search')
#def show_search():
#    renderedTemplate = render_template("search.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
#    response = make_response(renderedTemplate)
#    response = security_headers.add(response)
#    return response

#@application.route('/sign-out')
#def show_signout():
#    # Do a sign out here
#    # Redirect to index
#    response = make_response()
#    response.headers.set('Location: /')
#    response = security_headers.add(response)
#    return response

if __name__ == "__main__":
    application.run()