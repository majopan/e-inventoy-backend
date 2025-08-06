import pandas as pd # type: ignore
from django.http import HttpResponse
from .models import Dispositivo

def importar_excel(archivo):
    try:
        df = pd.read_excel(archivo)

        dispositivos = []
        for _, row in df.iterrows():
            dispositivo = Dispositivo(
                tipo=row.get("Tipo", ""),
                marca=row.get("Fabricante", ""),
                modelo=row.get("Modelo", ""),
                serial=row.get("Serial", ""),
                estado=row.get("Estado", ""),
                nombre_sede=row.get("Sede", ""),
                piso=row.get("Piso", ""),
                posicion=row.get("Posicion", ""),
                ubicacion=row.get("Ubicacion", ""),
                servicio=row.get("Servicio", ""),
                codigo_analitico=row.get("Codigo Analitico", ""),
                placa_cu=row.get("CU", ""),
                sistema_operativo=row.get("Sistema Operativo", ""),
                procesador=row.get("Procesador", ""),
                capacidad_disco_duro=row.get("Disco Duro", ""),
                capacidad_memoria_ram=row.get("Memoria RAM", ""),
                proveedor=row.get("Proveedor", ""),
                estado_propiedad=row.get("Estado Propiedad", ""),
                razon_social=row.get("Razon Social", ""),
                regimen=row.get("Regimen", ""),
            )
            dispositivos.append(dispositivo)

        Dispositivo.objects.bulk_create(dispositivos)
        return HttpResponse("Importación exitosa", status=201)
    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=500)

def exportar_excel():
    dispositivos = Dispositivo.objects.all().values()
    df = pd.DataFrame(list(dispositivos))

    response = HttpResponse(content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response["Content-Disposition"] = 'attachment; filename="dispositivos.xlsx"'

    df.to_excel(response, index=False)
    return response