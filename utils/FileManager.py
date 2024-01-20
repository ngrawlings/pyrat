class FileManager:
    def __init__(self):
        self.open_files = []

    def open_file(self, file_path):
        print("Opening file: " + file_path)
        file = open(file_path, 'rb')
        self.open_files.append(file)

    def close_file(self, file_path=None):
        print("Closing file: " + file_path)
        if file_path:
            for file in self.open_files:
                if file.name == file_path:
                    file.close()
                    self.open_files.remove(file)
                    break
        else:
            for file in self.open_files:
                file.close()
            self.open_files.clear()

    def read_chunk(self, file_path, chunk_size):
        for file in self.open_files:
            if file.name == file_path:
                return file.read(chunk_size)
        return None

    def is_file_open(self, file_path):
        for file in self.open_files:
            if file.name == file_path:
                return True
        return False

    
