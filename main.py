#! /usr/bin/env python
# -*- coding: utf-8 -*-
from functions import *
from datetime import datetime
from configure import Configure

config_file = "./config_otx.cfg"
config = Configure(config_file)


def main():
    otx = AlienVault(config)
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    local_rev = config.get_attribute('main', 'local_revision')
    remote_rev = config.get_attribute('main', 'remote_revision')

    if int(local_rev) == 0:
        print("Программа запускается впервые. Необходимо скачать БД")
        list_database = otx.get_database()
        for data in list_database:
            send(transform_data(patch))


    elif int(remote_rev) > int(local_rev):
        print("Checked updating from server...")
        list_patch = otx.get_patch()
        for patch in list_patch:
            send(transform_data(patch))

    else:
        print("ERROR!!!")


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
