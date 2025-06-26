from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist
from volatility3.framework.renderers import format_hints
import os
from volatility3.plugins.windows.vadinfo import VadInfo


class ProcdumpCustom(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.StringRequirement(name="dump-dir", description="Répertoire de sortie des dumps", optional=False),
            requirements.ListRequirement(name="pid", element_type=int, description="Liste des PID à dumper", optional=True)
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        dump_dir = self.config["dump-dir"]
        pids = self.config.get("pid", [])

        for proc in pslist.PsList.list_processes(self.context, kernel.name):
            pid = proc.UniqueProcessId
            image = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")

            if pids and pid not in pids:
                continue

            try:
                proc_layer = self.context.layers[proc.vol.layer_name]
                vad_root = proc.get_vad_root()

                for vad in vad_root.traverse():
                    try:
                        start = vad.get_start()
                        end = vad.get_end()
                        size = end - start
                        data = proc_layer.read(start, size, pad=True)

                        name = f"{image}_{pid}_{start:x}-{end:x}.dmp"
                        path = os.path.join(dump_dir, name)
                        with open(path, 'wb') as f:
                            f.write(data)

                        result = f"Dumpé à {path}"
                    except exceptions.InvalidAddressException:
                        result = "Adresse invalide pour cette région VAD"
                    except Exception as e:
                        result = f"Erreur dump VAD: {str(e)}"

                    yield (0, [format_hints.Hex(pid), image, result])

            except Exception as e:
                result = f"Erreur globale sur le processus : {str(e)}"
                yield (0, [format_hints.Hex(pid), image, result])

    def run(self):
        return renderers.TreeGrid(
            [("PID", format_hints.Hex), ("ImageFileName", str), ("Result", str)],
            self._generator()
        )
