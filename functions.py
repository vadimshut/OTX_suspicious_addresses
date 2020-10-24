import re
import requests
import socket


class AlienVault:
    def __init__(self, configure):
        self.__config = configure
        self.__reputation_server = self.__config.get_attribute('main', 'reputation_server')
        self.__url_reputation_server_revision = self.__reputation_server + 'reputation.rev'
        self.__url_reputation_database = self.__reputation_server + 'reputation.data'

    @staticmethod
    def get_text_data(url):
        """
        Отправляет get  запрос по URL и возвращает response в текстовом формате
        :return: content.text
        """
        content = requests.get(url)
        return content.text

    @staticmethod
    def checked_url(url):
        """Для проверки status_code."""
        return requests.get(url)

    @staticmethod
    def check_reputation_format(ln):
        r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
        return False if ln != "" and not r.match(ln) else True

    @staticmethod
    def __create_data_in_cef_format(data):
        """Метод прнинимает трансформирует данные из БД в CEF формат"""
        cef = f"""
            CEF:0|AlienvaultOTX|AlienvaultOTX|1.0.0|100|Suspicious Host|1|msg={data[3]} src={data[0]} 
            request= http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip={data[0]}
            cs1Label=Source Geo Country Code cs1={data[5]}                     
        """
        return cef

    def get_remote_rep_rev(self):
        """Получить значение обновления"""
        data = self.get_text_data(self.__url_reputation_server_revision)
        return data if data else None

    def download_reputation_database(self):
        print("Start downloading data from the server...")
        try:
            data = self.get_text_data(self.__url_reputation_database)
            remote_rev = self.get_text_data(self.__url_reputation_server_revision).rstrip()
            if remote_rev is not None:
                self.__config.set_attribute('main', 'length_old_file', str(len(data.split("\n"))))
                self.__config.set_attribute('main', 'local_revision', remote_rev)
            print("Database downloading successfully!")
            return data.split("\n")
        except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError):
            print("Error downloading database from server.")
            return None

    def transform_and_send_data(self, list_data):
        count_message = 0
        print("Start sending data to siem...")
        for data in list_data:
            if self.check_reputation_format(data) and data != "":
                if data[0] == "-":
                    continue
                elif data[0] == "+":
                    row_split = data[1:].split("#")
                else:
                    row_split = data.split("#")

                if len(row_split) == 8:

                    # min_priority = 2, min_reliability = 2
                    min_priority = self.__config.get_int('fields', 'min_priority')
                    min_reliability = self.__config.get_int('fields', 'min_reliability')
                    rel = int(row_split[1])
                    priority = int(row_split[2])
                    if min_priority <= priority and min_reliability <= rel:
                        cef = self.__create_data_in_cef_format(row_split)
                        self.__syslog(cef)
                        count_message += 1
        print(f"Успешно отправлено {count_message} индикаторов")

    def __syslog(self, message):
        host = self.__config.get_attribute('main', 'syslog_host')
        port = self.__config.get_int('main', 'syslog_port')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(message.encode(), (host, port))
        s.close()

#
#
#
#
#
# def get_patch(config, rep_server, revision):
#     # IF status_code >= 400, response.raise_for_status() вызывае ошибку и выполнение функции прерывается
#     # При нормальных условиях это происходит, когда revision=0.(при первом запуске)
#     response = checked_url(f"{rep_server}revisions/reputation.data_{revision}")
#     response.raise_for_status()
#     # IF status_code < 400, revision != 0, сравниваем количество строк в старом и новом файле
#     # len_old_file количество строк в старом файле
#     len_old_file = config.getint('main', 'length_old_file')
#     print('Объем данных предыдущего обновления ' + str(len_old_file))
#     # Получаем len_new_file количество строк в обновленном файле
#     url_for_new_file = 'https://reputation.alienvault.com/reputation.data'
#     len_new_file = len(get_url(url_for_new_file).split("\n"))
#     print('Объем данных нового обновления ' + str(len_new_file))
#     # Получаем значение rev, чтобы обновить его версию в конфиг файле revision (версия базы данных)
#     rev = get_url(f"{rep_server}reputation.rev")
#     # Если размеры фалов не равны, создаем строковую переменную patch которая содержит в себе только новые данные
#     if int(len_old_file) != int(len_new_file):
#         list_patch = get_url(url_for_new_file).split("\n")
#         patch = '\n'.join(list_patch[len_old_file:])
#         if rev is not None:
#             config.set('main', 'length_old_file', str(len_new_file))
#             config.set('main', 'revision', rev)
#             with open(config_file, 'w') as configfile:
#                 config.write(configfile)
#         print("Patch completed successfully")
#         return patch
#     else:
#         print('Не найдено новых данных для экспорта в вашу систему безопасности.\n')
#         if rev is not None:
#             config.set('main', 'length_old_file', str(len_new_file))
#             config.set('main', 'revision', rev)
#             with open(config_file, 'w') as configfile:
#                 config.write(configfile)
#
