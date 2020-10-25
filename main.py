#! /usr/bin/env python
# -*- coding: utf-8 -*-
from functions import *
from datetime import datetime
from configure import Configure

config_file = "./config_otx.cfg"
config = Configure(config_file)
otx = AlienVault(config)


def main():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    if int(config.get_attribute('main', 'local_revision')) == 0:
        print("Программа запускается впервые. Необходимо скачать БД")
        list_database = otx.get_database()
        for data in list_database:
            otx.transform_data(data)

    elif config.get_int('main', 'remote_revision') > config.get_int('main', 'local_revision'):
        print("Checked updating from server...")
        list_patch = otx.get_patch()
        for data in list_patch:
            otx.transform_data(data)

    else:
        print("You are have last data.")


if __name__ == '__main__':
    main()

    #     try:
    #         data = get_patch(reputation_server, local_rev)
    #         return data
    #     except requests.exceptions.HTTPError:
    #         print('Ошибка обновления данных с сервера')
    #
    #     print("Downloading complete database...")
    #     data = download_reputation_database(reputation_server)
    #     print(data)
