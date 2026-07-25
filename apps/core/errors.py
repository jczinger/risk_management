"""
Error handlers.

Custom handlers exist mainly so a 500 never leaks a traceback or a decrypted value
into a response, and so the pages keep the app's chrome instead of Django's bare
defaults.
"""

import logging

from django.shortcuts import render

logger = logging.getLogger("vms")


def permission_denied(request, exception=None):
    return render(request, "errors/403.html", status=403)


def page_not_found(request, exception=None):
    return render(request, "errors/404.html", status=404)


def server_error(request):
    # Django has already logged the traceback via django.request; this is only to
    # make the correlation obvious in the app's own log stream.
    logger.error("Unhandled error serving %s", request.path)
    return render(request, "errors/500.html", status=500)
