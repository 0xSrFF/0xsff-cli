import os
import importlib.util
from core.logger import log

def load_plugins():
    plugins = []
    plugin_dir = "plugins"
    
    if not os.path.exists(plugin_dir):
        return plugins

    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and filename != "__init__.py":
            module_name = filename[:-3]
            file_path = os.path.join(plugin_dir, filename)
            
            try:
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # We expect each plugin to have a 'run' function
                if hasattr(module, "run"):
                    plugins.append(module)
                    log(f"[+] Loaded plugin: {module_name}")
            except Exception as e:
                log(f"[!] Failed to load plugin {filename}: {e}")
                
    return plugins
