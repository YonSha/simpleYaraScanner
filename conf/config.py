import json
import psutil
from logger.logger import setup_logger


class Config:
    def __init__(self, filepath="./configuration.json"):
        self.__settings = self.__load_config(filepath)
        setup_logger()
        self.physical_cores_available =  psutil.cpu_count(logical=False)

    def __load_config(self, filepath):
        try:
            with open(filepath, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading configuration: {e}")
            return {}

    @property
    def maximum_processes(self):

        return self.__settings.get("maximum_processes", self.physical_cores_available - 1)

    @property
    def minimum_processes(self):
        return self.__settings.get("processes_usage").get("minimum_processes")
