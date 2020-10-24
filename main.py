#! /usr/bin/env python
# -*- coding: utf-8 -*-
from functions import *
import requests
from datetime import datetime
from configure import Configure

config_file = "./config_otx.cfg"
config = Configure(config_file)


# Разобраться для чего!!!!!!
# if config.getboolean('proxy', 'enable'):
#     print ("Using Proxy")
#     user = config.get('proxy', 'user')
#     password = config.get('proxy', 'password')
#     proxy_host = config.get('proxy', 'host')
#     proxy_port = config.getint('proxy', 'port')
#     proxy_support = urllib2.ProxyHandler({"http": "http://%s:%s@%s:%d" % (user, password, proxy_host, proxy_port)})
#     opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler)
#     urllib2.install_opener(opener)

#
def main():
    # while True:
    # reputation_server = config.get_attribute('main', 'reputation_server')
    local_rev = config.get_attribute('main', 'local_revision')
    otx = AlienVault(config)
    # remote_rev = get_url(f'{reputation_server}reputation.rev').rstrip()
    # config.set_attribute('main', 'remote_revision', remote_rev)
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    # print(f"Server data revision is {remote_rev}")
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