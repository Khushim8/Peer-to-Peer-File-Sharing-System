from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib
import os
import random
import pymysql

pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://user:password@db:3306/p2p_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database models
class Peer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FilePeer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    peer_id = db.Column(db.Integer, db.ForeignKey('peer.id'), nullable=False)

@app.route('/register_peer', methods=['POST'])
def register_peer():
    data = request.get_json()
    ip = data.get("ip")
    port = data.get("port")

    if not ip or not port:
        return jsonify({"status": "error", "message": "Missing ip or port"}), 400

    peer = Peer(ip_address=ip, port=port)
    db.session.add(peer)
    db.session.commit()

    print(f"✅ Registered Peer ID {peer.id}: {ip}:{port}")
    return jsonify({"peer_id": peer.id}), 200

@app.route('/register_file', methods=['POST'])
def register_file():
    data = request.get_json()
    file_hash = hashlib.sha256(data['file_name'].encode()).hexdigest()

    file = File.query.filter_by(file_hash=file_hash).first()
    if not file:
        file = File(file_name=data['file_name'], file_hash=file_hash)
        db.session.add(file)
        db.session.commit()

    file_peer = FilePeer(file_id=file.id, peer_id=data['peer_id'])
    db.session.add(file_peer)
    db.session.commit()

    print(f"📁 Registered file {file.file_name} with hash {file_hash} for peer {data['peer_id']}")
    return jsonify({'status': 'success', 'file_hash': file_hash})

@app.route('/search', methods=['GET'])
def search_file():
    file_hash = request.args.get('file_hash')
    file = File.query.filter_by(file_hash=file_hash).first()

    if not file:
        return jsonify({'status': 'error', 'message': 'File not found'})

    file_peers = FilePeer.query.filter_by(file_id=file.id).all()
    peers = []

    for fp in file_peers:
        peer = Peer.query.get(fp.peer_id)
        peers.append({'ip': peer.ip_address, 'port': peer.port})

    return jsonify({'status': 'success', 'file_name': file.file_name, 'peers': peers})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
