import os

from app import app


class VercelPrefixMiddleware:
	"""Remove Vercel's /api rewrite prefix before Flask routes the request."""

	def __init__(self, application):
		self.application = application

	def __call__(self, environ, start_response):
		path = environ.get("PATH_INFO", "")
		if os.environ.get("VERCEL") and (path == "/api" or
						  path.startswith("/api/")):
			environ["PATH_INFO"] = path[4:] or "/"
		return self.application(environ, start_response)


app.wsgi_app = VercelPrefixMiddleware(app.wsgi_app)
