from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return "<h1>Welcome to the local target</h1>"

@app.route('/search')
def search():
    query = request.args.get('query')
    return f"<h1>Search results for: {query}</h1>"

if __name__ == '__main__':
    app.run(port=5000)
