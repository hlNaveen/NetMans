from flask import Flask, render_template

app = Flask(__name__)

# Define routes
@app.route('/')
def index():
    # Render a basic template for the homepage
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)  # Run the Flask app in debug mode
