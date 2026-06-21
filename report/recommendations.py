RECOMMENDATIONS = {
    "Cross-Site Scripting (XSS)": {
        "fix": "Sanitize all user inputs and encode output using context-aware escaping.",
        "snippet": """# Python/Flask
from markupsafe import escape
safe_output = escape(user_input)

# Node.js/Express
const he = require('he');
const safe = he.encode(userInput);

# Nginx header
add_header Content-Security-Policy "default-src 'self'; script-src 'self'";""",
    },
    "SQL Injection": {
        "fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "snippet": """# Python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Node.js
db.query("SELECT * FROM users WHERE id = ?", [userId]);

# Java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);""",
    },
    "Blind SQL Injection (Time-Based)": {
        "fix": "Use parameterized queries. Implement a WAF and DB query timeout.",
        "snippet": """# Same as SQL Injection — use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Additional: set DB query timeout
SET statement_timeout = '5s';  -- PostgreSQL""",
    },
    "Missing CSRF Token": {
        "fix": "Generate and validate a CSRF token for every state-changing form submission.",
        "snippet": """# Python/Flask
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Django (built-in)
{% csrf_token %}  {# Add to every form in template #}

# Node.js/Express
const csrf = require('csurf');
app.use(csrf());""",
    },
    "Cookie Missing HttpOnly Flag": {
        "fix": "Set the HttpOnly flag on all session cookies.",
        "snippet": """# Python/Flask
response.set_cookie('session', value, httponly=True, secure=True, samesite='Lax')

# Node.js/Express
res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'Lax' });

# PHP
setcookie('session', $value, ['httponly' => true, 'secure' => true]);

# Nginx
proxy_cookie_path / "/; HttpOnly; Secure";""",
    },
    "Cookie Missing Secure Flag": {
        "fix": "Set the Secure flag on all cookies to prevent transmission over HTTP.",
        "snippet": """# Python/Flask
response.set_cookie('session', value, secure=True, httponly=True)

# Node.js
res.cookie('session', value, { secure: true, httpOnly: true });

# Apache
Header edit Set-Cookie ^(.*)$ $1;Secure;HttpOnly""",
    },
    "Cookie Missing SameSite Attribute": {
        "fix": "Set SameSite=Lax or SameSite=Strict on all cookies.",
        "snippet": """# Python/Flask
response.set_cookie('session', value, samesite='Lax')

# Node.js
res.cookie('session', value, { sameSite: 'lax' });

# Recommended: use Strict for admin sessions, Lax for general sessions""",
    },
    "Open Redirect": {
        "fix": "Validate redirect URLs against an allowlist of trusted domains.",
        "snippet": """# Python
from urllib.parse import urlparse
ALLOWED_HOSTS = ['yourdomain.com']
def safe_redirect(url):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return '/'
    return url

# Node.js
const allowedDomains = ['yourdomain.com'];
function safeRedirect(url) {
  const parsed = new URL(url);
  if (!allowedDomains.includes(parsed.hostname)) return '/';
  return url;
}""",
    },
    "Sensitive File Exposed": {
        "fix": "Remove sensitive files from the web root. Block access via server config.",
        "snippet": r"""# Nginx — block sensitive files
location ~* /(\.env|\.git|wp-config\.php|config\.php|phpinfo\.php) {
    deny all;
    return 404;
}

# Apache .htaccess
<FilesMatch "(\.env|\.git|config\.php|phpinfo\.php)">
    Order allow,deny
    Deny from all
</FilesMatch>""",
    },
    "Missing Security Header: Strict-Transport-Security": {
        "fix": "Add HSTS header to force HTTPS connections.",
        "snippet": """# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Node.js/Express
const helmet = require('helmet');
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));""",
    },
    "Missing Security Header: Content-Security-Policy": {
        "fix": "Define a strict CSP to prevent XSS and data injection.",
        "snippet": """# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';" always;

# Node.js/Express
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] }
}));""",
    },
    "Missing Security Header: X-Frame-Options": {
        "fix": "Add X-Frame-Options to prevent clickjacking.",
        "snippet": """# Nginx
add_header X-Frame-Options "SAMEORIGIN" always;

# Apache
Header always append X-Frame-Options SAMEORIGIN

# Node.js
res.setHeader('X-Frame-Options', 'SAMEORIGIN');""",
    },
    "Missing Security Header: X-Content-Type-Options": {
        "fix": "Add X-Content-Type-Options: nosniff.",
        "snippet": """# Nginx
add_header X-Content-Type-Options "nosniff" always;

# Apache
Header set X-Content-Type-Options "nosniff"

# Node.js
res.setHeader('X-Content-Type-Options', 'nosniff');""",
    },
    "No Rate Limiting on Login": {
        "fix": "Implement rate limiting, account lockout, and CAPTCHA on login endpoints.",
        "snippet": """# Node.js/Express
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts'
});
app.use('/login', loginLimiter);

# Python/Flask
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)
@app.route('/login', methods=['POST'])
@limiter.limit("10/minute")
def login(): ...""",
    },
    "Site Not Using HTTPS": {
        "fix": "Install an SSL certificate and redirect all HTTP traffic to HTTPS.",
        "snippet": """# Nginx — redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

# Free SSL: use Let's Encrypt
certbot --nginx -d yourdomain.com""",
    },
    "Secret Found in JS": {
        "fix": "Remove all secrets from client-side code. Use server-side API calls instead.",
        "snippet": """# Move API calls server-side
# BAD (in JS):
const apiKey = "sk_live_abc123...";

# GOOD: create a backend endpoint
# Frontend calls: /api/data
# Backend (Node.js):
app.get('/api/data', (req, res) => {
  const result = await fetch('https://api.service.com/data', {
    headers: { 'Authorization': process.env.API_KEY }
  });
  res.json(result);
});""",
    },
    "Broken Access Control — Header Bypass": {
        "fix": "Validate authorization server-side, never based on headers alone.",
        "snippet": """# Always check authorization in your application code
# BAD: trusting X-Original-URL or X-Forwarded-For
# GOOD:
def admin_route():
    if not current_user.is_admin:
        abort(403)
    # proceed with admin logic

# In Nginx, strip untrusted headers from upstream
proxy_set_header X-Original-URL "";
proxy_set_header X-Rewrite-URL "";""",
    },
    "Exposed API Endpoint": {
        "fix": "Add authentication to all API endpoints. Implement proper authorization checks.",
        "snippet": """# Node.js/Express — JWT middleware
const jwt = require('jsonwebtoken');
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!jwt.verify(token, process.env.SECRET)) return res.status(401).json({error: 'Unauthorized'});
  next();
}
app.use('/api', authMiddleware);

# Python/Flask
from functools import wraps
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not verify_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated""",
    },
    "Missing SPF Record": {
        "fix": "Add an SPF TXT record to your DNS to authorize mail servers.",
        "snippet": """# DNS TXT record
v=spf1 include:_spf.google.com include:sendgrid.net ~all

# For stricter policy (reject unauthorized):
v=spf1 include:_spf.google.com -all""",
    },
    "Missing DMARC Record": {
        "fix": "Add a DMARC TXT record at _dmarc.yourdomain.com",
        "snippet": """# DNS TXT record at _dmarc.yourdomain.com
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; ruf=mailto:dmarc@yourdomain.com; fo=1

# Start with p=none for monitoring, then move to p=quarantine, then p=reject
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com""",
    },
    "Subdomain Takeover Vulnerability": {
        "fix": "Remove the dangling DNS CNAME record immediately.",
        "snippet": """# 1. Remove the CNAME record from your DNS provider
# 2. Or re-register/claim the service the CNAME points to
# 3. Audit all subdomains regularly:
#    dig +short CNAME sub.yourdomain.com
#    Then check if the service is still active""",
    },
    "Dangerous HTTP Method Allowed: PUT": {
        "fix": "Disable unnecessary HTTP methods in server configuration.",
        "snippet": """# Nginx — allow only GET, POST, HEAD
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}

# Apache
<LimitExcept GET POST HEAD>
    Order allow,deny
    Deny from all
</LimitExcept>""",
    },
    "HTTP TRACE Method Enabled": {
        "fix": "Disable the TRACE method on all servers.",
        "snippet": """# Apache
TraceEnable off

# Nginx
if ($request_method = TRACE) {
    return 405;
}""",
    },
}


def get_recommendation(vuln_name):
    for key, rec in RECOMMENDATIONS.items():
        if key.lower() in vuln_name.lower() or vuln_name.lower() in key.lower():
            return rec
    return {
        "fix": "Review the vulnerability details and apply security best practices.",
        "snippet": "# Consult OWASP guidelines: https://owasp.org/www-project-top-ten/",
    }
