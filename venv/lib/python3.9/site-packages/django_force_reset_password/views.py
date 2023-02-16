from django.contrib import admin
from django.http import HttpResponseRedirect


class PassWordReset(admin.AdminSite):

    def login(self, request, extra_context=None):
        if request.method == 'POST':
            response = super(PassWordReset, self).login(request, extra_context=extra_context)
            if response.status_code == 302 and request.user.is_authenticated():
                if not "fpr" in request.session or request.session['fpr']:
                    request.session['fpr'] = True
                    return HttpResponseRedirect("/admin/password_change/")
            return response
        return super(PassWordReset, self).login(request, extra_context=extra_context)

    def password_change(self, request, extra_context=None):
        if request.method == 'POST':
            response = super(PassWordReset, self).password_change(request, extra_context=extra_context)
            if response.status_code == 302 and request.user.is_authenticated():
                request.session['fpr'] = False
            return response
        return super(PassWordReset, self).password_change(request, extra_context=extra_context)


pfr_login = PassWordReset().login
pfr_password_change = PassWordReset().admin_view(PassWordReset().password_change, cacheable=True)