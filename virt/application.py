from flask import Flask, render_template
import os

application = Flask(__name__)

@application.route('/')
@application.route('/index')
def show_index():
    full_filename = os.path.join('static', 'theme', 'images', 'MantaSecLogo-Outline-512.png')
    return render_template("index.html", user_image = full_filename)

if __name__ == "__main__":
    application.run()