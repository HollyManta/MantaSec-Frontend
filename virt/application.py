## Pip installed or default modules
from flask import Flask, request, render_template, Markup, make_response, redirect
import os
import MySQLdb
import bcrypt
import re

## Custom modules
import template_parts
import security_headers
import db_functions
import security_functions
import parser_nessus
import vulnerability_handling
import aggregator

## Set up the app, "application" is expected by Elastic Beanstalk
application = Flask(__name__)

db_functions.init()

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


@application.route('/upload', methods=['GET','POST'])
def show_upload(): 
    if request.method == 'POST':
        files = request.files.getlist('file[]')
        vulns = []
        for file in files:
            inputData = file.read()
            ## TODO - fix the return values for .check() to allow error handling
            if parser_nessus.check(inputData) > 0:
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


## Display the registration form (GET) or process a registration (POST)
@application.route('/register', methods=['GET','POST'])
def show_register(): 
    ## Process a registration
    if request.method == 'POST':
        ## Check that we received each parameter (email, password, confirm)
        paramList = request.form.to_dict().keys()
        if not ("email" in paramList and "password" in paramList and "confirm" in paramList):
            registrationErrors = "Error: Missing parameter!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)

        ## We have all the post variables so shorted them
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        ## Check if password and confirm match
        if (confirm != password):
            registrationErrors = "Error: Invalid email address!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)

        ## TODO - Check password complexity
        if (not security_functions.passStrongEnough(password)):
            registrationErrors = "Error: Password not strong enough!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)

        ## Check the email address is valid
        regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
        if not (re.search(regex,email)): 
            registrationErrors = "Error: Invalid email address!"
            renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent, registrationErrors = registrationErrors)
            response = make_response(renderedTemplate)
            response = security_headers.add(response)
        
        ## TODO - Check the email is not in use
        
        # If registration fails then contnue to load the template with the original email address
        #return redirect("/profile", code=302)
    renderedTemplate = render_template("register.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
    response = make_response(renderedTemplate)
    response = security_headers.add(response)
    return response


@application.route('/sign-out')
def show_signout():
    ## TODO - Do a sign out here
    ## TODO -  Redirect to index
    return redirect("/", code=302)


if __name__ == "__main__":
    application.run()