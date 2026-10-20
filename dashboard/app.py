"""Loopback-only HTTP UI. Every API request requires a per-launch bearer token."""
import argparse
import hmac
import secrets

from flask import Flask, jsonify, request, Response, send_from_directory
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, HTTPException
from werkzeug.serving import make_server
from dashboard.service import VPNService, validate_name


def create_app(service, token):
    app = Flask(__name__, static_folder='static')
    app.config['MAX_CONTENT_LENGTH'] = 4096

    @app.before_request
    def authorize():
        if request.host.split(':')[0] not in ('127.0.0.1', 'localhost'):
            return jsonify(error='Local access only.'), 403
        if request.path.startswith('/api/'):
            origin = request.headers.get('Origin')
            if origin and origin != f'http://{request.host}':
                return jsonify(error='Cross-origin access denied.'), 403
            expected = f'Bearer {token}'
            if not hmac.compare_digest(request.headers.get('Authorization', ''), expected):
                return jsonify(error='Open the private dashboard link from its terminal.'), 401

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(BadRequest)
    def bad_json(error):
        return jsonify(error='Invalid request.'), 400

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(error):
        return jsonify(error='Request is too large.'), 413

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error='Request could not be completed.'), error.code

    @app.errorhandler(Exception)
    def failure(error):
        # Do not serialize traceback, AWS responses, request bodies, or key-bearing files.
        return jsonify(error='Operation failed. Check AWS login, SSM connectivity and server readiness. Existing devices were not automatically removed.'), 503

    @app.get('/')
    def index():
        return send_from_directory(app.static_folder, 'index.html')

    @app.get('/api/status')
    def status():
        return jsonify(service.status())

    @app.post('/api/devices')
    def create():
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError('Provide a device name.')
        name = validate_name(data.get('name'))
        return jsonify(service.create(name)), 201

    @app.delete('/api/devices/<name>')
    def revoke(name):
        validate_name(name)
        service.revoke(name)
        return jsonify(ok=True)

    @app.get('/api/devices/<name>/<kind>')
    def artifact(name, kind):
        validate_name(name)
        if kind not in ('conf', 'qr'):
            return jsonify(error='Unknown file type.'), 404
        data = service.artifact(name, kind)
        extension, content_type = ('conf', 'application/octet-stream') if kind == 'conf' else ('png', 'image/png')
        return Response(data, content_type=content_type, headers={'Content-Disposition': f'attachment; filename="home-vpn-{name}.{extension}"'})

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--instance', help='Defaults to the current Terraform server output')
    parser.add_argument('--account', help='Expected AWS account; defaults to the Terraform output')
    parser.add_argument('--profile', default='terraform-admin')
    parser.add_argument('--region', default='ap-northeast-1')
    args = parser.parse_args()
    token = secrets.token_urlsafe(32)
    app = create_app(VPNService(instance=args.instance, account=args.account, profile=args.profile, region=args.region), token)
    server = make_server('127.0.0.1', args.port, app, threaded=True)
    print(f'Private dashboard: http://127.0.0.1:{server.server_port}/#{token}', flush=True)
    print('Loopback only. Keep this link private. Ctrl+C stops the dashboard.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
