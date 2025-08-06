from django.utils import timezone
from django.http import JsonResponse
from django.contrib.auth import logout
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

class InactivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Excluir ciertas rutas que no deben afectar la inactividad
        if request.path in ['/api/auth/login/', '/api/auth/keepalive/', '/api/validate/']:
            return self.get_response(request)
            
        try:
            # Autenticar usando JWT para asegurar que el usuario es válido
            jwt_auth = JWTAuthentication()
            auth_result = jwt_auth.authenticate(request)
            
            if auth_result is not None:
                user, _ = auth_result
                request.user = user
                
                # Verificar inactividad solo para usuarios autenticados que no sean celadores
                if user.is_authenticated and getattr(user, 'rol', None) != 'celador':
                    last_activity = getattr(user, 'last_activity', None)
                    
                    if last_activity:
                        inactive_period = timezone.now() - last_activity
                        if inactive_period.total_seconds() > 1800:  # 30 minutos
                            logout(request)
                            return JsonResponse(
                                {
                                    'error': 'Sesión cerrada por inactividad',
                                    'detail': 'No se detectó actividad durante 30 minutos'
                                }, 
                                status=401
                            )
        except AuthenticationFailed:
            pass  # Si falla la autenticación, dejar que otros middlewares manejen
        
        response = self.get_response(request)
        
        # Actualizar marca de tiempo de actividad para usuarios autenticados no celadores
        if hasattr(request, 'user') and request.user.is_authenticated and getattr(request.user, 'rol', None) != 'celador':
            request.user.last_activity = timezone.now()
            request.user.save(update_fields=['last_activity'])
            
        return response