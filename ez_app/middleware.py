import logging
import time
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger('ez_app')

class LoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        request.start_time = time.time()
        if request.path.startswith('/api/'):
            logger.debug(f"Request: {request.method} {request.get_full_path()}")

    def process_response(self, request, response):
        duration = time.time() - request.start_time
        if request.path.startswith('/api/'):
            logger.debug(f"Response: {response.status_code} {request.get_full_path()} (Duration: {duration:.2f}s)")
        return response