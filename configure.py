import configparser


class Configure:
    def __init__(self, cfg_file):
        self.__config_file = cfg_file
        self.__config = configparser.ConfigParser()

    def get_attribute(self, section, attr_name):
        self.__config.read(self.__config_file, encoding="utf-8")
        return self.__config.get(section, attr_name)

    def set_attribute(self, section, attr_name, value):
        self.__config.read(self.__config_file)
        self.__config.set(section, attr_name, value)
        with open(self.__config_file, 'w') as file:
            self.__config.write(file)

    def get_int(self, section, attr_name):
        return int(self.get_attribute(section, attr_name))