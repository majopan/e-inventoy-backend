from django.core.management.base import BaseCommand
from rich.progress import Progress
from time import sleep

class Command(BaseCommand):
    help = "Ejemplo de comando con una barra de progreso morada"

    def handle(self, *args, **kwargs):
        self.stdout.write("Comenzando tarea...\n")

        # Creamos el progreso y personalizamos el color
        with Progress(transient=True) as progress:
            task = progress.add_task("[magenta]Ejecutando migraciones...", total=10)

            while not progress.finished:
                sleep(0.5)
                progress.update(task, advance=1)
        
        self.stdout.write("\nTarea completada\n")
