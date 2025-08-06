from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import RolUser, Sede, Servicios, Posicion, Dispositivo, Movimiento

class RolUserCreationForm(UserCreationForm):
    sedes = forms.ModelMultipleChoiceField(
        queryset=Sede.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label="Sedes asignadas"
    )

    class Meta:
        model = RolUser
        # Se utilizan 'password1' y 'password2' para validar la confirmación de contraseña
        fields = ['username', 'rol', 'nombre', 'celular', 'documento', 'email', 'password1', 'password2', 'sedes']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Se establece que el email es obligatorio y se normaliza el mensaje de error
        self.fields['email'].required = True
        self.fields['email'].error_messages = {'required': 'El correo electrónico es obligatorio.'}

    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        # Normalizamos el email a minúsculas y eliminamos espacios en blanco
        email = email.lower().strip()
        if not email:
            raise forms.ValidationError("El correo electrónico es obligatorio.")
        return email

class RolUserChangeForm(UserChangeForm):
    sedes = forms.ModelMultipleChoiceField(
        queryset=Sede.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        required=False,
        label="Sedes asignadas"
    )

    class Meta:
        model = RolUser
        fields = ['username', 'rol', 'nombre', 'celular', 'documento', 'email', 'sedes']

    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        return email.lower().strip()

# Formulario para la creación y edición de sedes
class SedeForm(forms.ModelForm):
    class Meta:
        model = Sede
        fields = ['nombre', 'ciudad', 'direccion']

# Formulario para la creación y edición de servicios
class ServiciosForm(forms.ModelForm):
    class Meta:
        model = Servicios
        fields = ['nombre', 'codigo_analitico', 'sede']

# Formulario para la creación y edición de posiciones
class PosicionForm(forms.ModelForm):
    class Meta:
        model = Posicion
        fields = ['piso', 'nombre', 'descripcion']

# Formulario para la creación y edición de dispositivos
class DispositivoForm(forms.ModelForm):
    class Meta:
        model = Dispositivo
        fields = [
            'tipo', 'estado', 'marca', 'razon_social', 'regimen', 'modelo', 'serial',
            'placa_cu', 'posicion', 'sede', 'tipo_disco_duro', 'capacidad_disco_duro',
            'tipo_memoria_ram', 'capacidad_memoria_ram', 'ubicacion'
        ]

    def clean_serial(self):
        """
        Validación personalizada para verificar que el serial sea único.
        """
        serial = self.cleaned_data.get('serial')
        if Dispositivo.objects.filter(serial=serial).exists():
            raise forms.ValidationError("El número de serie ya está registrado.")
        return serial

# Formulario para la creación y edición de movimientos
class MovimientoForm(forms.ModelForm):
    class Meta:
        model = Movimiento
        fields = ['dispositivo', 'encargado', 'ubicacion_origen', 'ubicacion_destino', 'observacion']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['encargado'].queryset = RolUser.objects.filter(rol='coordinador')



