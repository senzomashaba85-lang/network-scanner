from flask import Flask, request, jsonify
from src.scanner import scan_network, scan_ports

app = Flask(__name__)

@app.route("/scan", methods=["GET"])
def scan():
    # Get subnet from query string, default to 192.168.0.0/24
    subnet = request.args.get("subnet", "192.168.0.0/24")
    hosts = scan_network(subnet)
    results = []
    for h in hosts:
        ports = scan_ports(h)
        results.append({"ip": h, "open_ports": ports})
    return jsonify({"subnet": subnet, "results": results})

if __name__ == "__main__":
    # Run the API server
    app.run(host="0.0.0.0", port=5000)
