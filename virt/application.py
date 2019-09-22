from flask import Flask, request, render_template, Markup, make_response

import os
import template_parts
import security_headers
import parser_nessus
import vulnerability_handling

application = Flask(__name__)

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
            if parser_nessus.check(inputData) == 0:
                if len(vulns) == 0:
                    vulns = parser_nessus.parse(inputData)  # First file we can parse, so we're starting fresh
                else:
                    vulns = parser_nessus.merge(vulns, inputData)   # Already got some vulns, so merge the results
            else:
                print("Unsupported file type") 
                   
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

#@application.route('/profile')
#def show_profile():
#    renderedTemplate = render_template("profile.html", sidebar = sidebar, navbar = navbar, headercontent = headercontent)
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