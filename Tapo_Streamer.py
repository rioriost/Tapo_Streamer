#!/usr/bin/env python3

# standard library
import configparser
import ipaddress
import os
import sys
import pathlib

# third party library
try:
    import PySimpleGUI as sg
except ModuleNotFoundError:
    try:
        os.system('python3 -m pip install pysimplegui')
        import PySimpleGUI as sg
    except ModuleNotFoundError: # pip doesn't resolve dependency, so we have to install it with brew
        os.system('brew install tcl-tk')
        import PySimpleGUI as sg

try:
    import rtsp
except ModuleNotFoundError:
    os.system('python3 -m pip install rtsp')
    import rtsp

try:
    from PIL import Image, ImageTk
except ModuleNotFoundError:
    os.system('python3 -m pip install pillow')
    from PIL import Image, ImageTk

try:
    import keyring
except ModuleNotFoundError:
    os.system('python3 -m pip install keyring')
    import keyring

# Application Name
APP_NAME = "Tapo_Streamer"

# main procedure
def open_window(user_id: str, user_pw: str, row_col: dict, hosts:dict) -> None:
    layout = [
        [[sg.Image(filename='', key="image-{}".format(hosts[f"stream{row}-{col}"])) for col in range(row_col["col"])] for row in range(row_col["row"])],
        [sg.Button('Connect', size=(10, 1), key ='-connect-'),
         sg.Button('Disconnect', size=(10, 1), key = '-disconnect-')]
         ]
    is_streaming = False
    window = sg.Window('Tapo Camera', layout, location=(32, 32), finalize=True, element_justification='left', font='Helvetica 18')
    clients = {f"{host}": None for host in hosts.values() if host != ""}
    rtsp_urls = {f"{host}": f"rtsp://{user_id}:{user_pw}@{host}:554/stream2" for host in hosts.values() if host != ""}
    while True:
        event, values = window.read(timeout=1)
        if event == sg.WIN_CLOSED:
            break
        elif event == "-connect-":
            if is_streaming is False:
                for host in hosts.values():
                    if host != "":
                        print(f"Connecting to {host}...")
                        clients[host] = rtsp.Client(rtsp_server_uri=rtsp_urls[host])
                        is_streaming = True
        elif event == "-disconnect-":
            if is_streaming is True:
                is_streaming = False
                for host in hosts.values():
                    if host != "":
                        print(f"Disconnecting to {host}...")
                        clients[host].close()
                        clients[host] = None
                        img = Image.new('RGB', (640, 480), color=0)
                        window[f"image-{host}"].update(data=ImageTk.PhotoImage(img))
        if is_streaming is True:
            for host in hosts.values():
                if host != "":
                    try:
                        frame = clients[host].read()
                        window[f"image-{host}"].update(data=ImageTk.PhotoImage(frame))
                    except:
                        print(f"Reconnecting to {host}...")
                        clients[host] = rtsp.Client(rtsp_server_uri=rtsp_urls[host])
    window.close()

def validate_ip(ip: str) -> bool:
    if ip is None:
        return False
    if ip == "": # empty string is valid
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def input_number(prompt: str) -> int:
    num = 0
    while num == 0:
        try:
            num = int(input(prompt))
        except ValueError:
            print("Please enter a valid number.")
    return num

def input_ip_address(prompt: str) -> str:
    ip = None
    while validate_ip(ip) is False:
        ip = input(prompt)
    return ip

def init_hosts() -> None:
    config_path = pathlib.Path(f"~/Library/Preferences/{APP_NAME}/config.ini").expanduser()
    if config_path.exists() is False:
        print(f"Config file not found, creating one in {config_path}")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            row_num = input_number("Please enter the number of rows for streams e.g. 2: ")
            col_num = input_number("Please enter the number of columns for streams e.g. 3: ")
        except KeyboardInterrupt:
            print("\n\nKeyboardInterrupt, exiting...")
            sys.exit(1)

        hosts = {f"stream{row}-{col}": "" for row in range(row_num) for col in range(col_num)}

        try:
            while True:
                for key, host in hosts.items():
                    tmp_ip = None
                    while validate_ip(tmp_ip) is False:
                        tmp_ip = input_ip_address(f"IP address for {key}: ")
                    hosts[key] = tmp_ip
                if sum(v == "" for v in hosts.values()) == row_num * col_num:
                    print("Please enter at least one host IP address.")
                else:
                    break
        except KeyboardInterrupt:
            print("\n\nKeyboardInterrupt, exiting...")
            sys.exit(1)

        config = configparser.ConfigParser()
        config["LAYOUT"] = {"row": row_num, "col": col_num}
        config["HOSTS"] = hosts
        with open(config_path, "w") as f:
            config.write(f)

    config = configparser.ConfigParser()
    config.read(config_path)
    return {"row": config["LAYOUT"].getint("row"), "col": config["LAYOUT"].getint("col")}, dict(config["HOSTS"])

def init_account() -> dict:
    key_id = "user_id"
    key_pw = "user_pw"

    user_id = keyring.get_password(APP_NAME, key_id)
    try:
        while user_id is None or user_id == "":
            keyring.set_password(APP_NAME, key_id, input("Please enter your Tapo ID, part before '@': "))
            user_id = keyring.get_password(APP_NAME, key_id)
    except KeyboardInterrupt:
        print("\n\nKeyboardInterrupt, exiting...")
        sys.exit(1)

    user_pw = keyring.get_password(APP_NAME, key_pw)
    try:
        while user_pw is None or user_pw == "":
            keyring.set_password(APP_NAME, key_pw, input("Please enter your Tapo Password : "))
            user_pw = keyring.get_password(APP_NAME, key_pw)
    except KeyboardInterrupt:
        print("\n\nKeyboardInterrupt, exiting...")
        sys.exit(1)

    return user_id, user_pw

def main() -> None:
    user_id, user_pw = init_account()
    row_col, hosts = init_hosts()
    open_window(user_id, user_pw, row_col, hosts)

if __name__ == '__main__':
    main()
