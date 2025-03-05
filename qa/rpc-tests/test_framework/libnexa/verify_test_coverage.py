#!/usr/bin/env python3

import os

def get_libnexa_api_methods():
    cur_dir = os.path.dirname(__file__)
    libnexa_rel_path = '../../../../src/libnexa/libnexa.h'
    libnexa_abs_path = os.path.join(cur_dir, libnexa_rel_path)
    methods = []
    with open(libnexa_abs_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("SLAPI"):
                line = line.split("(")[0]
                function_name = line.split(" ")[-1]
                methods.append(function_name)
    return methods
