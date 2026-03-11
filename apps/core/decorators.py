from functools import wraps
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path())
            try:
                user_role = request.user.profile.role
            except Exception:
                user_role = 'viewer'
            if user_role not in roles:
                return HttpResponseForbidden(
                    '<div style="font-family:sans-serif;padding:2rem;">'
                    '<h3>403 — ไม่มีสิทธิ์เข้าถึง</h3>'
                    f'<p>ต้องการ role: {", ".join(roles)}</p>'
                    '<p><a href="/">กลับหน้าหลัก</a></p></div>'
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def analyst_required(view_func):
    return role_required('admin', 'analyst')(view_func)


def admin_required(view_func):
    return role_required('admin')(view_func)
