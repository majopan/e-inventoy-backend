from django.apps import AppConfig

class DispositivosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dispositivos'
    label = 'dispositivos' 
   # Importa las señales para que se activen
