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
    def __get_status_code(url):
        """Получить status_code."""
        return requests.get(url)

    @staticmethod
    def __check_reputation_format(ln):
        r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
        return False if ln == "" or not r.match(ln) else True

    def get_remote_rev(self):
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
        new_remote_rev = self.get_remote_rev()
        remote_rev = self.__config.get_attribute('main', 'remote_revision')
        if self.__config.get_int('main', 'local_revision') == 0:
            self.__config.set_attribute('main', 'local_revision', new_remote_rev)
            self.__config.set_attribute('main', 'remote_revision', new_remote_rev)
        else:
            self.__config.set_attribute('main', 'local_revision', remote_rev)
            self.__config.set_attribute('main', 'remote_revision', new_remote_rev)

    def get_database(self):
        print("Start downloading the database...")
        try:
            data = self.__get_text_data(self.__url_reputation_database)
            remote_rev = self.__get_text_data(self.__url_remote_revision).rstrip()
            if remote_rev is not None:
                self.__change_revision()
                print("Database download completed successfully!")
                return data.split("\n")

        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
            print("Database download ERROR!")
            return None

    def transform_data(self, list_data):
        if list_data is None:
            print("No data to update.")
            return False
        print("Start sending IOC...")
        count_cef_msg = 0
        for data in list_data:
            if self.__check_reputation_format(data):
                if data[0] == "-":
                    continue
                elif data[0] == "+":
                    row_split = data[1:].split("#")
                else:
                    row_split = data.split("#")
                if len(row_split) == 8:
                    # print(row_split)
                    min_priority = self.__config.get_int('fields', 'min_priority')
                    min_reliability = self.__config.get_int('fields', 'min_reliability')
                    reliability = int(row_split[1])
                    priority = int(row_split[2])
                    if min_priority <= priority and min_reliability <= reliability:
                        cef = self.__create_data_in_cef_format(row_split)
                        self.__syslog(cef)
                        count_cef_msg += 1
        print(f"{count_cef_msg} IOC were successfully sent to SIEM.")

    def get_patch(self):
        remote_revision = self.get_remote_rev()
        url = f"{self.__reputation_server}revisions/reputation.data_{remote_revision}"
        status_code = self.__get_status_code(url)
        if status_code:
            self.__change_revision()
            response = self.__get_text_data(url)
            return response.split("\n") if len(response) > 0 else None

        return None
