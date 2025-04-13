from flask import Flask, request, jsonify, redirect, session, url_for, render_template_string
from flask_cors import CORS
import os
import requests
import logging
import random
from jwt import decode
import traceback
from datetime import datetime
import time
from urllib.parse import urlparse, quote

# Enhanced logging configuration with timestamp and level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuration
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN')
CLIENT_ID = os.environ.get('APP_CLIENT_ID')
REDIRECT_URI = os.environ.get('REDIRECT_URI')
TOKEN_URL = f"https://{COGNITO_DOMAIN}/oauth2/token"
CLIENT_SECRET = os.environ.get('APP_CLIENT_SECRET')
API_BASE_URL = os.environ.get('API_GATEWAY_URL')

# Get domain from API Gateway URL for cookie settings
api_gateway_domain = urlparse(API_BASE_URL).netloc if API_BASE_URL else None

# Enhanced session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',  # Required for cross-domain
    SESSION_COOKIE_DOMAIN=api_gateway_domain,
    SESSION_COOKIE_PATH='/',
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
    SESSION_REFRESH_EACH_REQUEST=True
)

# Configure CORS with enhanced settings
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost", 
            "http://localhost:80",
            API_BASE_URL,
            f"https://{api_gateway_domain}",
            "https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com",
            "https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com/prod",
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "expose_headers": ["Set-Cookie"]
    }
})

# Utility functions for token verification and logging
def log_token_details(token, token_type=""):
    """
    Decode and log token details while checking expiration
    Args:
        token: JWT token to decode
        token_type: Type of token (ID, Access, etc.)
    Returns:
        tuple: (decoded token contents, is token expired)
    """
    try:
        decoded = decode(token, options={"verify_signature": False})
        exp_time = datetime.fromtimestamp(decoded.get('exp', 0))
        is_expired = datetime.now() > exp_time
        
        logger.info(f"=== {token_type} Token Details ===")
        logger.info(f"Username: {decoded.get('cognito:username')}")
        logger.info(f"Expiration: {exp_time}")
        logger.info(f"Is Expired: {is_expired}")
        logger.info(f"Token Preview: {token[:10]}...{token[-10:]}")
        logger.info("=" * 40)
        
        return decoded, is_expired
    except Exception as e:
        logger.error(f"Token decode error: {str(e)}")
        return None, True

def verify_session_state():
    """
    Verify and log current session state
    Returns:
        dict: Current session state information
    """
    logger.info("=== Verifying Session State ===")
    state = {
        'has_id_token': 'id_token' in session,
        'has_access_token': 'access_token' in session,
        'has_refresh_token': 'refresh_token' in session,
        'has_username': 'username' in session
    }
    logger.info(f"Session State: {state}")
    
    if state['has_id_token']:
        decoded, is_expired = log_token_details(session['id_token'], "ID")
        state['token_valid'] = decoded is not None and not is_expired
    else:
        state['token_valid'] = False
    
    logger.info(f"Session Valid: {state['token_valid']}")
    logger.info("=" * 40)
    return state

def debug_session():
    """Log detailed session information for debugging"""
    logger.info("\n=== SESSION DEBUG ===")
    logger.info(f"Session ID: {session.sid if hasattr(session, 'sid') else 'No ID'}")
    logger.info(f"Session Contents: {dict(session)}")
    logger.info(f"Request Cookies: {dict(request.cookies)}")
    logger.info(f"Session Cookie Name: {app.session_cookie_name}")
    logger.info(f"Session Cookie Domain: {app.config.get('SESSION_COOKIE_DOMAIN')}")
    logger.info("=" * 40)

# HTML Templates
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .login-container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .login-button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
        }
        .login-button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Welcome</h1>
        <a href="{{ login_url }}" class="login-button">Login with Cognito</a>
    </div>
</body>
</html>
'''

HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Home</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 2rem;
            max-width: 800px;
            margin: 0 auto;
        }
        .container {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .color-button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            text-decoration: none;
            display: inline-block;
            margin: 5px;
        }
        .color-button:hover {
            background-color: #0056b3;
        }
        .color-display {
            margin-top: 1rem;
            padding: 1rem;
            border-radius: 4px;
        }
    </style>
    <script>
        async function getColor() {
            try {
                const response = await fetch('{{ api_base_url }}/get-color', {
                    headers: {
                        'Authorization': 'Bearer {{ id_token }}',
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include'
                });
                const data = await response.json();
                const colorDisplay = document.getElementById('colorDisplay');
                colorDisplay.style.backgroundColor = data.color;
                colorDisplay.textContent = data.color;
            } catch (error) {
                console.error('Error:', error);
                document.getElementById('colorDisplay').textContent = 'Error: ' + error;
            }
        }

        function handleLogout() {
            // Clear any stored data
            localStorage.clear();
            sessionStorage.clear();
            
            // Clear cookies
            document.cookie.split(";").forEach(function(c) {
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
            });
            
            // Redirect to logout endpoint
            window.location.href = '{{ api_base_url }}/logout';
            
            // Prevent any cached redirects
            return false;
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}!</h1>
        <button onclick="getColor()" class="color-button">Get Random Color V1</button>
        <div id="colorDisplay" class="color-display"></div>
        <button onclick="return handleLogout()" class="color-button">Logout</button>
    </div>
</body>
</html>
'''


# Route Handlers
@app.route('/')
@app.route('/login')
def login():
    """Handle login route and initial authentication"""
    logger.info("\n=== Login Route Accessed ===")
    logger.info(f"Session before processing: {dict(session)}")
    
    # Check if we received an authorization code
    code = request.args.get('code')
    if code:
        logger.info(f"Authorization code received: {code[:10]}...")
        return handle_callback(code)
    
    session_state = verify_session_state()
    logger.info(f"Session state at login: {session_state}")
    
    if session_state['token_valid']:
        logger.info("Valid session found, rendering home page directly")
        return render_template_string(
            HOME_PAGE,
            username=session.get('username'),
            id_token=session.get('id_token'),
            api_base_url=API_BASE_URL
        )
    
    login_url = f"https://{COGNITO_DOMAIN}/login?client_id={CLIENT_ID}&response_type=code&scope=email+openid+profile&redirect_uri={REDIRECT_URI}"
    logger.info(f"No valid session, generated login URL: {login_url}")
    return render_template_string(LOGIN_PAGE, login_url=login_url)

def handle_callback(code):
    """Handle OAuth callback with code"""
    logger.info("\n=== Processing Callback ===")
    try:
        logger.info(f"1. Exchanging code for tokens...")
        token_response = requests.post(
            TOKEN_URL,
            data={
                'grant_type': 'authorization_code',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'code': code,
                'redirect_uri': REDIRECT_URI
            }
        )
        
        logger.info(f"2. Token Response Status: {token_response.status_code}")
        logger.info(f"3. Token Response Body: {token_response.text[:100]}...")
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            return jsonify({'error': 'Failed to get token'}), 400
        
        tokens = token_response.json()
        logger.info("4. Successfully received tokens")

        # Clear existing session and make it permanent
        session.clear()
        session.permanent = True
        
        # Store tokens in session
        session['id_token'] = tokens['id_token']
        session['access_token'] = tokens['access_token']
        session['refresh_token'] = tokens['refresh_token']
        
        # Verify and log token details
        decoded, is_expired = log_token_details(tokens['id_token'], "ID")
        if decoded:
            session['username'] = decoded.get('cognito:username')
            logger.info(f"5. Set username in session: {session['username']}")
        
        # Force session save
        session.modified = True
        
        logger.info(f"6. Final session state: {dict(session)}")
        
        # Render home page directly instead of redirecting
        return render_template_string(
            HOME_PAGE,
            username=session.get('username'),
            id_token=session.get('id_token'),
            api_base_url=API_BASE_URL
        )
        
    except Exception as e:
        logger.error("=== Callback Error ===")
        logger.error(f"Error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Authentication failed', 'details': str(e)}), 400

@app.route('/oauth2/callback')
def callback():
    """Backup callback handler"""
    logger.info("\n=== Callback Route Accessed ===")
    logger.info(f"Full Request URL: {request.url}")
    code = request.args.get('code')
    
    if not code:
        logger.error("No authorization code received")
        return jsonify({'error': 'No code received'}), 400
    
    return handle_callback(code)

@app.route('/home')
def home():
    """Handle home route with authentication check"""
    logger.info("\n=== Home Route Accessed ===")
    debug_session()
    logger.info(f"1. Request Headers: {dict(request.headers)}")
    
    session_state = verify_session_state()
    logger.info(f"2. Session State: {session_state}")
    
    if not session_state['token_valid']:
        logger.warning("3. Invalid session, rendering login page")
        login_url = f"https://{COGNITO_DOMAIN}/login?client_id={CLIENT_ID}&response_type=code&scope=email+openid+profile&redirect_uri={REDIRECT_URI}"
        return render_template_string(LOGIN_PAGE, login_url=login_url)
    
    logger.info(f"4. Rendering home page for user: {session.get('username')}")
    return render_template_string(
        HOME_PAGE,
        username=session.get('username'),
        id_token=session.get('id_token'),
        api_base_url=API_BASE_URL
    )

@app.route('/get-color')
def get_color():
    """Handle get-color API endpoint with authentication"""
    logger.info("=== Get-Color Route Accessed ===")
    debug_session()
    session_state = verify_session_state()
    
    if not session_state['token_valid']:
        logger.error("Unauthorized access attempt to get-color")
        return jsonify({
            'error': 'Unauthorized',
            'details': 'Invalid or missing token',
            'session_state': session_state
        }), 401
    
    colors = ['#FF0000', '#00FF00', '#0000FF', '#FFFF00', '#FF00FF', '#00FFFF']
    color = random.choice(colors)
    logger.info(f"Selected color: {color}")
    
    return jsonify({'color': color})

@app.route('/logout')
def logout():
    """Handle logout with proper Cognito signout"""
    logger.info("=== Logout Route Accessed ===")
    debug_session()
    
    try:
        # Clear session
        session.clear()
        logger.info("Session cleared")

        # Construct Cognito logout URL
        # Note: Using 'logout_uri' instead of 'logout_uri' and adding client_id
        cognito_logout_url = (
            f"https://{COGNITO_DOMAIN}/logout?"
            f"client_id={CLIENT_ID}&"
            f"response_type=code&"
            f"redirect_uri={quote(REDIRECT_URI)}"
        )
        
        logger.info(f"Constructed logout URL: {cognito_logout_url}")
        
        # Create response
        response = redirect(cognito_logout_url)
        
        # Clear all related cookies
        cookies_to_clear = ['session', 'id_token', 'access_token', 'refresh_token']
        for cookie_name in cookies_to_clear:
            response.delete_cookie(
                cookie_name,
                domain=api_gateway_domain,
                path='/',
                secure=True,
                samesite='None'
            )
            # Also try clearing without domain
            response.delete_cookie(
                cookie_name,
                path='/',
                secure=True,
                samesite='None'
            )
        
        logger.info("Cookies cleared")
        logger.info(f"Response headers: {dict(response.headers)}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Logout failed', 'details': str(e)}), 500


@app.route('/debug-session')
def debug_session_endpoint():
    """Endpoint for debugging session state"""
    return jsonify({
        'session': dict(session),
        'cookies': dict(request.cookies),
        'headers': dict(request.headers),
        'session_config': {
            'domain': app.config.get('SESSION_COOKIE_DOMAIN'),
            'secure': app.config.get('SESSION_COOKIE_SECURE'),
            'samesite': app.config.get('SESSION_COOKIE_SAMESITE'),
            'path': app.config.get('SESSION_COOKIE_PATH')
        }
    })

# Enhanced request logging
@app.before_request
def log_request_info():
    """Log details of incoming requests"""
    logger.info("\n=== New Request ===")
    logger.info(f"Path: {request.path}")
    logger.info(f"Method: {request.method}")
    logger.info(f"Headers: {dict(request.headers)}")
    logger.info(f"Args: {dict(request.args)}")
    logger.info(f"Cookies: {dict(request.cookies)}")
    logger.info(f"Session: {dict(session)}")
    logger.info("=" * 40)

# Enhanced response handling with CORS
@app.after_request
def after_request(response):
    """Handle CORS and log response details"""
    logger.info("\n=== Response ===")
    logger.info(f"Status Code: {response.status_code}")
    
    origin = request.headers.get('Origin')
    allowed_origins = [
        "http://localhost",
        "http://localhost:80",
        API_BASE_URL,
        f"https://{api_gateway_domain}",
        "https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com",
        "https://26oj1y6xsa.execute-api.us-east-1.amazonaws.com/prod"
    ]
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Expose-Headers'] = 'Set-Cookie'
    
    logger.info(f"Response Headers: {dict(response.headers)}")
    logger.info("=" * 40)
    return response

if __name__ == '__main__':
    logger.info("=== Starting Application ===")
    logger.info(f"Environment Variables Set: {list(os.environ.keys())}")
    logger.info(f"API Gateway Domain: {api_gateway_domain}")
    logger.info(f"Session Cookie Domain: {app.config['SESSION_COOKIE_DOMAIN']}")
    logger.info("=" * 40)
    app.run(host='0.0.0.0', port=80)
