#! /usr/bin/env python
# -*- coding: utf-8 -*-
from functions import *
from datetime import datetime
from configure import Configure
import time
import schedule

config_file = "./config_otx.cfg"
config = Configure(config_file)
otx = AlienVault(config)


def main():
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    time.sleep(1)
    if int(config.get_attribute('main', 'local_revision')) == 0:
        print("Программа запускается впервые. Необходимо скачать БД")
        time.sleep(1)
        list_database = otx.get_database()
        otx.transform_data(list_database)

    elif int(otx.get_remote_rev()) > config.get_int('main', 'local_revision'):
        print("Checking for updates...")
        list_patch = otx.get_patch()
        otx.transform_data(list_patch)

    else:
        print("You have the latest data version.")


if __name__ == '__main__':
    schedule.every().hours.do(main)
    while True:
        schedule.run_pending()

