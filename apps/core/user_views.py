import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.http import require_POST, require_http_methods
from .decorators import admin_required
from .models import UserProfile
from .audit import audit


@admin_required
def user_list(request):
    from django_otp.plugins.otp_totp.models import TOTPDevice
    users = User.objects.select_related('profile').order_by('username')
    otp_users = set(TOTPDevice.objects.filter(confirmed=True).values_list('user_id', flat=True))
    return render(request, 'core/user_list.html', {'users': users, 'otp_users': otp_users})


@admin_required
@require_POST
def user_add(request):
    try:
        data = json.loads(request.body)
    except Exception:
        data = request.POST
    username   = (data.get('username') or '').strip()
    email      = (data.get('email') or '').strip()
    password   = (data.get('password') or '').strip()
    first_name = (data.get('first_name') or '').strip()
    last_name  = (data.get('last_name') or '').strip()
    role       = data.get('role') or 'analyst'
    department = (data.get('department') or '').strip()
    phone      = (data.get('phone') or '').strip()
    if not username or not password:
        return JsonResponse({'ok': False, 'error': 'username และ password จำเป็น'}, status=400)
    if User.objects.filter(username=username).exists():
        return JsonResponse({'ok': False, 'error': f'username "{username}" มีอยู่แล้ว'}, status=400)
    user = User.objects.create_user(username=username, email=email, password=password,
                                    first_name=first_name, last_name=last_name)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.role = role; profile.department = department; profile.phone = phone
    profile.save()
    audit(request, 'user_add', 'User', user.pk, f'Added user {username} role={role}')
    return JsonResponse({'ok': True, 'id': user.pk, 'username': user.username})


@admin_required
def user_get(request, pk):
    user = get_object_or_404(User, pk=pk)
    try:
        profile = user.profile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user)
    return JsonResponse({'ok': True, 'id': user.pk, 'username': user.username,
        'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name,
        'is_active': user.is_active, 'role': profile.role,
        'department': profile.department, 'phone': profile.phone})


@admin_required
@require_http_methods(['GET', 'POST'])
def user_edit(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == 'GET':
        return user_get(request, pk)
    try:
        data = json.loads(request.body)
    except Exception:
        data = request.POST
    user.email = (data.get('email') or '').strip()
    user.first_name = (data.get('first_name') or '').strip()
    user.last_name = (data.get('last_name') or '').strip()
    user.is_active = bool(data.get('is_active', True))
    if data.get('password'):
        user.set_password(data['password'].strip())
    user.save()
    profile, _ = UserProfile.objects.get_or_create(user=user)
    old_role = profile.role
    profile.role = data.get('role') or profile.role
    profile.department = (data.get('department') or '').strip()
    profile.phone = (data.get('phone') or '').strip()
    profile.save()
    detail = f'Edited user {user.username}'
    if old_role != profile.role:
        detail += f' role: {old_role} → {profile.role}'
    audit(request, 'user_edit', 'User', pk, detail)
    return JsonResponse({'ok': True})


@admin_required
@require_POST
def user_delete(request, pk):
    if request.user.pk == pk:
        return JsonResponse({'ok': False, 'error': 'ไม่สามารถลบตัวเองได้'}, status=400)
    user = get_object_or_404(User, pk=pk)
    username = user.username
    user.delete()
    audit(request, 'user_delete', 'User', pk, f'Deleted user {username}')
    return JsonResponse({'ok': True})


@admin_required
@require_POST
def user_toggle_active(request, pk):
    if request.user.pk == pk:
        return JsonResponse({'ok': False, 'error': 'ไม่สามารถปิดตัวเองได้'}, status=400)
    user = get_object_or_404(User, pk=pk)
    user.is_active = not user.is_active
    user.save(update_fields=['is_active'])
    status_label = 'enabled' if user.is_active else 'disabled'
    audit(request, 'user_toggle', 'User', pk, f'{status_label} user {user.username}')
    return JsonResponse({'ok': True, 'is_active': user.is_active})
