#! /usr/bin/env python
# -*- coding: utf-8 -*-
from functions import *
from datetime import datetime
from configure import Configure

config_file = "./config_otx.cfg"
config = Configure(config_file)


def main():

    local_rev = config.get_attribute('main', 'local_revision')
    otx = AlienVault(config)
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print(f"Local revision is {local_rev}")

    if int(local_rev) == 0:
        print("Программа запускается впервые. Необходимо скачать БД")
        list_data = otx.download_reputation_database()
        otx.transform_and_send_data(list_data)

    # if int(remote_rev) > int(local_rev):
    #     print("Checked updating from server...")
    #     try:
    #         data = get_patch(reputation_server, local_rev)
    #         return data
    #     except requests.exceptions.HTTPError:
    #         print('Ошибка обновления данных с сервера')
    #
    #     print("Downloading complete database...")
    #     data = download_reputation_database(reputation_server)
    #     print(data)


if __name__ == '__main__':
    main()
