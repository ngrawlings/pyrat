import json

class Macros:
    def __init__(self, filepath):
        self.filepath = filepath
        self.macros = self._load()

    def _load(self):
        try:
            with open(self.filepath) as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}
        return data

    def get(self, name):
        return self.macros.get(name, None)
    
    def set(self, name, macro):
        self.macros[name] = macro
        self._save()

    def _save(self):
        with open(self.filepath, 'w') as file:
            json.dump(self.macros, file)

    def delete(self, name):
        for macro in self.macros:
            if macro['name'] == name:
                self.macros.remove(macro)
                self.save_macros()
                return True
        return False
