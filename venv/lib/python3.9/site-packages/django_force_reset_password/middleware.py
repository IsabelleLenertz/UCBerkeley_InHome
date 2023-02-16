from django.http import HttpResponseRedirect
from django.conf import settings
import re


class FPRCheck(object):
    def process_request(self, request):
        if request.user.is_authenticated() \
                and re.match(r'^/admin/?', request.path) \
                and (not "fpr" in request.session or ("fpr" in request.session and request.session['fpr'])) \
                and not re.match(r"/admin/password_change|/admin/logout", request.path):
            return HttpResponseRedirect("/admin/password_change/")