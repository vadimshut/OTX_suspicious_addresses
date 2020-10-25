import re
import requests
import socket


class AlienVault:
    def __init__(self, configure):
        self.__config = configure
        self.__reputation_server = self.__config.get_attribute('main', 'reputation_server')
        self.__local_rev = self.__config.get_attribute('main', 'local_revision')
        self.__url_remote_revision = self.__reputation_server + 'reputation.rev'
        self.__url_reputation_database = self.__reputation_server + 'reputation.data'
        self.__host = self.__config.get_attribute('main', 'syslog_host')
        self.__port = self.__config.get_int('main', 'syslog_port')

    @staticmethod
    def __get_text_data(url):
        """Возвращает response в текстовом формате"""
        return requests.get(url).text

    @staticmethod
    def __checked_url(url):
        """Получить status_code."""
        return requests.get(url)

    @staticmethod
    def __check_reputation_format(ln):
        r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
        return False if ln == "" or not r.match(ln) else True

    def __get_remote_rev(self):
        """Получить значение обновления"""
        data = self.__get_text_data(self.__url_remote_revision).rstrip()
        return data if data else None

    @staticmethod
    def __create_data_in_cef_format(data):
        """Метод прнинимает трансформирует данные из БД в CEF формат"""
        cef = f"""
            CEF:0|AlienvaultOTX|AlienvaultOTX|1.0.0|100|Suspicious Host|1|msg={data[3]} src={data[0]} 
            request= http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip={data[0]}
            cs1Label=Source Geo Country Code cs1={data[5]}                     
        """
        return cef

    def __syslog(self, message):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(message.encode(), (self.__host, self.__port))
        s.close()

    def __change_revision(self):
        new_remote_rev = self.__get_remote_rev()
        old_remote_rev = self.__config.get_attribute('main', 'remote_revision')
        self.__config.set_attribute('main', 'local_revision', old_remote_rev)
        self.__config.set_attribute('main', 'remote_revision', new_remote_rev)

    def get_database(self):
        try:
            data = self.__get_text_data(self.__url_reputation_database)
            remote_rev = self.__get_text_data(self.__url_remote_revision).rstrip()
            if remote_rev is not None:
                self.__change_revision()
                return data.split("\n")
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
            return None

    def transform_data(self, list_data):
        for data in list_data:
            if self.__check_reputation_format(data):
                if data[0] == "-":
                    continue
                elif data[0] == "+":
                    row_split = data[1:].split("#")
                else:
                    row_split = data.split("#")
                if len(row_split) == 8:
                    min_priority = self.__config.get_int('fields', 'min_priority')
                    min_reliability = self.__config.get_int('fields', 'min_reliability')
                    reliability = int(row_split[1])
                    priority = int(row_split[2])
                    if min_priority <= priority and min_reliability <= reliability:
                        cef = self.__create_data_in_cef_format(row_split)
                        self.__syslog(cef)

    def get_patch(self):
        revision = self.__get_remote_rev()
        response = self.__checked_url(f"{self.__url_remote_revision}revisions/reputation.data_{revision}")
        return response

# response.raise_for_status()
