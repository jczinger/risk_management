"""Cross-cutting views: health check and error pages."""

from django.db import connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt

from .access import public_view


@public_view("container and reverse-proxy health probe")
@never_cache
@csrf_exempt
def healthz(request):
    """
    Liveness/readiness probe for Docker and the reverse proxy.

    Confirms the process is up *and* that Postgres answers, which is the failure
    mode worth catching — gunicorn will happily serve 500s with a dead database.
    Deliberately returns no version or tenant information to an unauthenticated
    caller.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:  # noqa: BLE001 - any DB failure is the same answer
        return JsonResponse({"status": "error", "database": "unavailable"}, status=503)

    return JsonResponse({"status": "ok"})
