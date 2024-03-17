import base64
import random
import signal
import sqlite3
import struct
import urllib.parse
import uuid
from typing import List, Dict
from IPython import embed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from aiohttp import ClientSession, web
import requests
import socket
import collections
import hmac
import json
import hashlib
import websockets
import argparse
import asyncio
import sys
import os
import time
import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.completion import NestedCompleter
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.logging import RichHandler
from rich.pretty import pretty_repr, Pretty
from rich.table import Table
import logging

AppKey = ""
AppSecret = ""
Token = ''
AesKey = ''
force_nonce = ''
disable_retry = False
max_retry_times = 2
retry_delay = 3
extra_header = {}
http_urls = []
host, port = '0.0.0.0', 0
websockets_list: List[web.WebSocketResponse] = []
websocket_verify_headers = "DingtalkStreamPushForward"
not_count_events = [
    "user_add_org",
    "user_modify_org",
    "user_leave_org",
    "user_active_org",
    "org_dept_create",
    "org_dept_modify",
    "org_dept_remove",
    "org_change",
    "label_user_change",
    "label_conf_add",
    "label_conf_del",
    "label_conf_modify",
    "org_admin_add",
    "org_admin_remove",
    "industry_medical_user_add",
    "org_annual_certification_submission"
]
now = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
requestUserAgent = f"DingtalkStreamPushForward v1.0 created on {now} (+https://github.com/MeiHuaGuangShuo/DingtalkStreamPushForward)"
WS_CONNECT_URL = "https://api.dingtalk.com/v1.0/gateway/connections/open"
prepared = False
stream_checker = collections.deque([], 50)
allow_tickets = []
websocket_times = [0, 0, 0]
console = Console()
logging.basicConfig(
    level='INFO',
    format="%(message)s",
    datefmt="[%Y-%m-%d %H:%M:%S]",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger('rich')


async def request_connection(request: web.Request):
    clientIp = request.headers.get("CF-Connecting-IP", request.remote)
    d = await request.json()
    if AppKey == d.get("clientId") and AppSecret == d.get("clientSecret"):
        ticket = str(uuid.uuid1())
        allow_tickets.append(ticket)
        if clientIp in ["0.0.0.0", "127.0.0.1", "::1"]:
            connect_host = "localhost"
        else:
            connect_host = get_local_ip()
        return web.json_response({'endpoint': f"ws://{connect_host}:{port}/", 'ticket': ticket})
    else:
        return web.json_response({'reason': "Auth failed.", 'code': 401}, status=401)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def generate_signature(timestamp, appSecret):
    signature_string = str(timestamp) + "\n" + appSecret
    signature = hmac.new(appSecret.encode(), signature_string.encode(), hashlib.sha256)
    encoded_signature = base64.b64encode(signature.digest()).decode('utf-8')
    return encoded_signature


def decrypt(encrypt_data, aes_key):
    aes_key = base64.b64decode(aes_key + '=')
    encrypt_data = base64.b64decode(encrypt_data)
    iv = encrypt_data[:16]
    encrypted_msg = encrypt_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_msg)
    msg_len = int.from_bytes(decrypted_data[:4], byteorder="big")
    msg = decrypted_data[4:4 + msg_len]
    return msg.decode()


def encrypt(data, token, aesKey, appKey, timestamp=None, nonce=None):
    aesKey = base64.b64decode(aesKey + '=')
    if timestamp is None:
        timestamp = str(int(time.time() * 1000))
    if isinstance(timestamp, int):
        timestamp = str(timestamp)
    if nonce is None:
        nonce = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 16))
    msg_len = struct.pack('>I', len(data))
    data_to_encrypt = nonce.encode('utf-8') + msg_len + (data + appKey).encode('utf-8')
    iv = aesKey[:16]
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
    encrypted_msg = base64.b64encode(encrypted_data).decode('utf-8')
    logger.debug(f"Nonce: {nonce}, TimeStamp: {timestamp}, Token: {token}, enc_msg: {encrypted_msg}\n"
                 f"sorted_data: {''.join(sorted([nonce, timestamp, token, encrypted_msg]))}")
    signature = hashlib.sha1(''.join(sorted([nonce, timestamp, token, encrypted_msg])).encode()).hexdigest()
    return {'msg_signature': signature, 'encrypt': encrypted_msg, 'timeStamp': timestamp, 'nonce': nonce}


async def open_connection():
    request_headers = {
        'User-Agent': requestUserAgent
    }
    request_body = {
        'clientId'     : AppKey,
        'clientSecret' : AppSecret,
        'subscriptions': [
            {'type': 'EVENT', 'topic': '*'},
            {'type': 'CALLBACK', 'topic': '/v1.0/im/bot/messages/get'},
            {'type': 'CALLBACK', 'topic': '/v1.0/im/bot/messages/delegate'},
            {'type': 'CALLBACK', 'topic': '/v1.0/card/instances/callback'},
        ],
        'ua'           : requestUserAgent,
        'localIp'      : get_local_ip()
    }
    logger.info(f'Requesting stream connection...\n'
                f'Headers:\n{pretty_repr(request_headers)}\n'
                f'Body:\n{pretty_repr(request_body)}')
    response = requests.post(WS_CONNECT_URL, headers=request_headers, json=request_body)
    http_body = response.json()
    if not response.ok:
        logger.error(f"Open connection failed, Reason: {response.reason}, Response: {http_body}")
        if response.status_code == 401:
            logger.warning(f"The AppKey or AppSecret maybe inaccurate")
            sys.exit(1)
        return None
    return response.json()


async def route_message(json_message: dict, websocket: websockets.WebSocketServer):
    global websocket_times
    result = ''
    not_commit = False
    try:
        msg_type = json_message.get('type', '')
        headers = json_message.get('headers', {})
        data = json.loads(json_message.get('data', {}))
        topic = headers.get('topic', '')
        if headers.get('eventId', str(time.time())) in stream_checker:
            logger.warning(f"Same Callback. ID:{headers.get('eventId', str(time.time()))}")
            await websocket.send(json.dumps({
                'code'   : 200,
                'headers': headers,
                'message': 'OK',
                'data'   : json_message['data'],
            }))
            return result
        else:
            stream_checker.append(headers.get('eventId', str(time.time())))
        if msg_type == 'SYSTEM':
            if topic == 'disconnect':
                result = 'disconnect'
                logger.warning(
                    f"[System] Client was offered to disconnect, message: {json_message}")
            else:
                logger.info(f"[System] topic: {topic}")
            headers['topic'] = "pong"
            await websocket.send(json.dumps({
                'code'   : 200,
                'headers': headers,
                'message': 'OK',
                'data'   : json_message['data'],
            }))
        else:
            show_json = json_message.copy()
            show_json['data'] = data
            logger.info(pretty_repr(show_json))
            if 'eventType' in headers:
                data['EventType'] = headers['eventType']
                if headers['eventType'] in not_count_events:
                    not_commit = True
                else:
                    try:
                        is_exist = counter.execute(f"SELECT * FROM `events` WHERE event_type='{headers['eventType']}'",
                                                   result=True)
                        if is_exist:
                            counter.execute(
                                f"UPDATE `events` SET times=times+1 WHERE event_type='{headers['eventType']}';")
                        else:
                            counter.execute(
                                f"INSERT INTO `events` (event_type, times) VALUES ('{headers['eventType']}', 1);")
                        counter.db.commit()
                    except:
                        console.print_exception(show_locals=True)
            data['corpId'] = headers.get('eventCorpId')
            loop.create_task(bcc(json_message, data))
            await websocket.send(json.dumps({
                'code'   : 200,
                'headers': headers,
                'message': 'OK',
                'data'   : json_message['data'],
            }))
        counter.execute(f"INSERT INTO `received` (data, TimeStamp) VALUES (?, ?)",
                        (json.dumps(json_message), int(time.time() * 1000)))
        if not not_commit:
            now_date = "Received_" + datetime.datetime.now().strftime("%Y_%m")
            is_exist = counter.execute(f"SELECT * FROM `counts` WHERE name='{now_date}'", result=True)
            if is_exist:
                counter.execute(f"UPDATE `counts` SET times=times+1 WHERE name='{now_date}';")
            else:
                counter.execute(f"INSERT INTO `counts` (name, times) VALUES ('{now_date}', 1);")
            counter.db.commit()
            all_times = counter.execute("SELECT SUM(times) FROM counts WHERE name LIKE 'Received_%'", result=True)
            if all_times:
                all_times = all_times[0][0]
            is_exist = counter.execute(f"SELECT * FROM `counts` WHERE name='{now_date}'", result=True)
            websocket_times = [websocket_times[0] + 1, is_exist[0][1] if is_exist else 0, all_times]
    
    except Exception:
        console.print_exception(show_locals=True)
    return result


async def main_stream():
    while ...:
        connection: Dict = await open_connection()
        if not connection:
            if connection is None:
                logger.error(f'Open websocket connection failed')
                logger.warning(f"Websocket Connection will be reconnected after 5 seconds")
                await asyncio.sleep(5)
                logger.warning(f"Reconnecting...")
                continue
            if not connection:
                logger.error(f'Request connection failed!')
            return
        uri = '%s?ticket=%s' % (connection['endpoint'], urllib.parse.quote_plus(connection['ticket']))
        headers = {'User-Agent': requestUserAgent}
        try:
            async with websockets.connect(uri, extra_headers=headers) as websocket:
                logger.info(f"Websocket connected")
                try:
                    async for raw_message in websocket:
                        json_message = json.loads(raw_message)
                        route_result = await route_message(json_message, websocket)
                        if route_result == "disconnect":
                            break
                except asyncio.CancelledError:
                    logger.warning(f"Closing the websocket connections...")
                    await websocket.close()
                    break
                except Exception as err:
                    console.print_exception()
                    logger.warning(f"The stream connection will be reconnected after 5 seconds")
                    await asyncio.sleep(5)
        except Exception as err:
            console.print_exception()
            logger.warning(f"The stream connection will be reconnected after 5 seconds")
            await asyncio.sleep(5)
    
    logger.info(f"Stream connection was stopped.")


async def bcc(raw, data):
    try:
        loop.create_task(websocket_send(raw))
        url_param = {}
        if not AesKey and not Token:
            return
        if "conversationType" in data:
            timeStamp = data.get('timeStamp', str(int(time.time() * 1000)))
            headers = {"sign": generate_signature(timeStamp, AppSecret), "timestamp": str(timeStamp)}
            return
        else:
            data['EventType'] = raw['headers']['eventType']
            new_data = {}
            trans_data = data.copy()
            for k, v in trans_data.items():
                new_data[k[0].upper() + k[1:]] = v
            new_data['CorpId'] = raw['headers']['eventCorpId']
            headers = {}
        headers.update(extra_header)
        async with ClientSession() as s:
            for u in http_urls:
                url = str(u[0])
                try:
                    tried = 0
                    curr_time = str(int(time.time() * 1000))
                    enc_data = encrypt(json.dumps(new_data), Token, AesKey, u[1], curr_time,
                                       force_nonce if force_nonce else None)
                    data = {'encrypt': enc_data['encrypt']}
                    url_param['signature'] = enc_data['msg_signature']
                    url_param['msg_signature'] = enc_data['msg_signature']
                    url_param['timestamp'] = enc_data['timeStamp']
                    url_param['nonce'] = enc_data['nonce']
                    if url_param:
                        if '?' not in url:
                            url += '?'
                        else:
                            url += '&'
                        url += '&'.join([f'{k}={v}' for k, v in url_param.items()])
                    while tried < max_retry_times:
                        if disable_retry:
                            tried = max_retry_times
                        res = await s.post(url, json=data, headers=headers)
                        resp = await res.text()
                        if url_param:
                            try:
                                if res.headers.get('Content-Type') == 'application/json' and resp.startswith(
                                        '{') and 'encrypt' in resp:
                                    resp = await res.json()
                                    if (dec_mes := decrypt(resp['encrypt'], AesKey)) == 'success':
                                        re_enc = encrypt('success', Token, AesKey, u[1], resp.get('timeStamp'),
                                                         resp.get('nonce'))
                                        if resp == re_enc:
                                            logger.info(
                                                f"Push url:\n> {u[0]}\nStatus [{res.status}]:\n> {pretty_repr(await res.text())}")
                                            tried = max_retry_times
                                            try:
                                                is_exist = counter.execute(f"SELECT * FROM `webhooks` WHERE url=?",
                                                                           (u[0],), result=True)
                                                if is_exist:
                                                    counter.execute(f"UPDATE `webhooks` SET times=times+1 WHERE url=?;",
                                                                    (u[0],))
                                                else:
                                                    counter.execute(
                                                        f"INSERT INTO `webhooks` (url, times) VALUES (?, 1);", (u[0],))
                                                counter.db.commit()
                                            except:
                                                console.print_exception(show_locals=True)
                                            continue
                                        logger.error(
                                            f"[red]Error Callback Result[/]\nURL: {url}\nPostData: {data}\n"
                                            f"Result:\n  {pretty_repr(resp)}\nDecrypt message:\n{pretty_repr(dec_mes)}\n"
                                            f"ReEncrypt ('success'|{Token}|{AesKey}|{u[1]}|{resp.get('timeStamp')}|{resp.get('nonce')}):\n  {pretty_repr(re_enc)}")
                                    else:
                                        logger.error(
                                            f"[red]Error Callback Result[/]: [white bold]Wrong Message[/]\nURL: {url}\n"
                                            f"PostData: {data}\n"
                                            f"Result:\n  {pretty_repr(resp)}\nDecrypt message:\n{pretty_repr(dec_mes)}")
                                else:
                                    logger.error(
                                        f"[red]Error Callback Result[/]\nURL: {url}\nPostData: {data}\n"
                                        f"Content-Type: {res.headers.get('Content-Type')}\nResult:\n{pretty_repr(resp)}")
                                await asyncio.sleep(retry_delay)
                                tried += 1
                                continue
                            except json.JSONDecodeError:
                                logger.error(f"[red]Error Callback Result[/]: [white bold]Not JSON response[/]\n"
                                             f"URL: {u}\nPostData: {data}\n"
                                             f"Result:\n  {pretty_repr(resp)}")
                                await asyncio.sleep(retry_delay)
                                tried += 1
                                continue
                            except UnicodeDecodeError:
                                logger.error(
                                    f"[red]Error Callback Result[/]: [white bold]Wrong AesKey Callback Reply[/]\n"
                                    f"URL: {u}\nPostData: {data}\n"
                                    f"Result:\n  {pretty_repr(resp)}")
                                await asyncio.sleep(retry_delay)
                                tried += 1
                                continue
                            except Exception:
                                console.print_exception(show_locals=True)
                                await asyncio.sleep(retry_delay)
                                tried += 1
                                continue
                        logger.info(f"Push url:\n> {u}\nStatus [{res.status}]:\n> {pretty_repr(await res.text())}")
                        tried = 2
                except Exception as err:
                    console.print_exception(max_frames=2, show_locals=True)
                    logger.error(f"{err.__class__.__name__}: {err}")
    except Exception:
        console.print_exception(max_frames=2, show_locals=True)


async def websocket_send(data):
    global websockets_list
    for w in websockets_list:
        try:
            await w.send_json(data)
        except Exception:
            console.print_exception(max_frames=2, show_locals=True)
            try:
                websockets_list.remove(w)
                await w.close()
            except:
                pass


async def handle_websocket(request: web.Request):
    global websockets_list
    request_headers = request.headers
    ticket = request.query.get('ticket', '')
    clientIp = request_headers.get("CF-Connecting-IP", request.remote)
    logger.info(f"Connect Request from {clientIp}")
    if ticket not in allow_tickets:
        logger.warning(f"{clientIp} Authentication failed. Headers: {request_headers}")
        return web.Response(status=400)
    allow_tickets.remove(ticket)
    websocket = web.WebSocketResponse()
    await websocket.prepare(request)
    logger.info(f"{clientIp} Connected.")
    websockets_list.append(websocket)
    try:
        async for message in websocket:
            try:
                message = json.loads(message.data)
            except Exception as err:
                logger.error(
                    f'Invalid Response.\n{err.__class__.__name__}: {err}\nClient: {clientIp}\nMessage:\n>{pretty_repr(message)}')
                await websocket.close(code=1008, message=b'Invalid Response.')
                break
            else:
                logger.info(f"{clientIp} -> [{message.get('code', 'Error')}]")
    except Exception as err:
        logger.error(f'{clientIp} -> [bold red]{err.__class__.__name__}[/]: [white bold]{err}[/]')
    websockets_list.remove(websocket)
    logger.info(f"{clientIp} Disconnected.")


def get_prompt():
    text = FormattedText([
        ('', f'[{datetime.datetime.now().strftime("%H:%M:%S")}'),
    ])
    if AesKey and AppKey:
        text.append(('', f" HTTP: {len(http_urls)}"))
    if port:
        text.append(('', f" Websocket: {len(websockets_list)}"))
    text.append(('', f' Received: {websocket_times[0]}/'))
    month_times = websocket_times[1]
    per = month_times / 5000
    text.append(('#ff0000' if per > 0.8 else '#ffff00' if per > 0.5 else '', f'{month_times}'))
    text.append(('', f'/{websocket_times[2]}'))
    text.append(('', '] > '))
    return text


def main():
    global websocket_task
    session = PromptSession(history=FileHistory('history.txt'),
                            auto_suggest=AutoSuggestFromHistory())
    completer = NestedCompleter.from_nested_dict({
        'get_websocket'    : None,
        'start_websocket'  : None,
        'close_websocket'  : None,
        'restart_websocket': None,
        'get_webhook'      : None,
        'add_webhook'      : None,
        'analysis'         : None,
        'remove_webhook'   : None,
        'sql'              : None,
        'eval'             : None,
        'ipython'          : None,
        'exit'             : None,
        'stop'             : None
    })
    while ...:
        try:
            with patch_stdout(True):
                command = session.prompt(message=get_prompt, completer=completer)
            if not command:
                continue
            if command in ['exit', 'stop']:
                stop()
                break
            elif command == 'ipython':
                embed(colors='Neutral', using='asyncio')
            elif command == 'get_websocket':
                text = ""
                for ws in websockets_list:
                    text += f"{ws.remote_address[0]}\n"
                text += "-- End of the websocket list --"
                console.print(text)
            elif command == 'start_websocket':
                if not websocket_task.done():
                    console.print("Websocket server is already running")
                else:
                    websocket_task = loop.create_task(main_websocket())
                    console.print("Websocket server started")
            elif command == 'close_websocket':
                for ws in websockets_list:
                    try:
                        asyncio.run(ws.close(code=1000, message=b"Server closed."))
                    except Exception as err:
                        console.print(f"Err while closing websocket from {ws.remote_address[0]}\n"
                                      f"[bold red]{err.__class__.__name__}[/]: [white bold]{err}[/]")
                    else:
                        console.print(f"Closed websocket connection from {ws.remote_address[0]}")
                websocket_task.cancel()
                console.print("Stopped websocket server")
            elif command == 'restart_websocket':
                websocket_task.cancel()
                console.print("Websocket server stopped")
                websocket_task = loop.create_task(main_websocket())
                console.print("Websocket server restarted")
            elif command == 'get_webhook':
                text = ""
                for w in http_urls:
                    text += f"{w}\n"
                text += "-- End of the webhook list --"
                console.print(text)
            elif command == 'analysis':
                res = counter.execute("SELECT * FROM `events` ORDER BY times DESC;", result=True)
                t = Table()
                t.add_column("EventType")
                t.add_column("Times")
                for r in res:
                    t.add_row(*[Pretty(x) for x in r])
                console.print(t)
                res = counter.execute("SELECT * FROM `webhooks` ORDER BY times DESC;", result=True)
                t = Table()
                t.add_column("Webhook Url")
                t.add_column("Pushed Times")
                for r in res:
                    t.add_row(*[Pretty(x) for x in r])
                console.print(t)
                res = counter.execute("SELECT * FROM `counts` WHERE name LIKE 'Received_%' ORDER BY name DESC;",
                                      result=True)
                _all_times = counter.execute("SELECT SUM(times) FROM counts WHERE name LIKE 'Received_%'", result=True)
                if _all_times:
                    _all_times = _all_times[0][0]
                t = Table()
                t.add_column("History")
                t.add_column("Received Times")
                for r in res:
                    t.add_row(*[Pretty(x) for x in r])
                t.add_row("[green bold]ALL Summary[/]", Pretty(_all_times))
                console.print(t)
                cd = datetime.datetime.now().date()
                dd = {}
                for i in range(7):
                    td = cd - datetime.timedelta(days=i)
                    fd = td.strftime('%Y-%m-%d')
                    st = int(datetime.datetime(td.year, td.month, td.day, 0, 0, 0).timestamp()) * 1000
                    et = int(datetime.datetime(td.year, td.month, td.day, 23, 59, 59).timestamp()) * 1000
                    counter.cursor.execute("SELECT COUNT(*) FROM received WHERE TimeStamp BETWEEN ? AND ?", (st, et))
                    c = counter.cursor.fetchone()[0]
                    dd[fd] = c
                t = Table()
                t.add_column("Date")
                t.add_column("Received Times")
                for k, v in dd.items():
                    t.add_row(Pretty(k), Pretty(v))
                t.add_row("[green bold]Week Summary[/]", Pretty(sum(list(dd.values()))))
                console.print(t)
            elif command.startswith('add_webhook'):
                if len(command.split(' ', 1)) != 2:
                    console.print("Usage: add_webhook <URL>")
                    continue
                url = command.split(' ', 1)[1].split(' ', 1)
                if len(url) == 1:
                    http_urls.append([url[0], AesKey])
                else:
                    if url[1]:
                        if url[1].startswith('ding'):
                            console.print(f"Added webhook: {url[0]}({url[1]})")
                            http_urls.append([url[0], url[1]])
                        else:
                            console.print(f"[red]Error webhook AppKey[/]: {url[0]} - ({url[1]})")
                    else:
                        http_urls.append([url[0], AesKey])
                        console.print(f"Added webhook: {url[0]}")
                console.print(f"Added webhook url: {url}")
            elif command.startswith('remove_webhook'):
                if len(command.split(' ', 1)) != 2:
                    console.print("Usage: remove_webhook <URL>")
                    continue
                url = command.split(' ', 1)[1]
                if url not in http_urls:
                    console.print(f"url [{url}] not in the webhook list")
                    continue
                http_urls.remove(url)
                console.print(f"Removed webhook url: {url}")
            elif command.startswith('eval '):
                res = eval(command.split(' ', 1)[1])
                console.print(res)
            elif command.startswith('sql '):
                res = counter.execute(command.split(' ', 1)[1], result=True)
                console.print(res)
            else:
                console.print(f"Unknown command: {command}")
        except Exception:
            console.print_exception(show_locals=True)
    stop()


async def main_websocket():
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()


def stop(*args):
    stream_task.cancel()
    if websocket_task:
        websocket_task.cancel()
    loop.stop()
    counter.close()
    logger.info("Exited.")
    os._exit(0)


class Counter:
    db: sqlite3.Connection = None
    cursor: sqlite3.Cursor = None
    
    def __init__(self):
        pass
    
    @classmethod
    def connect(cls, databaseName: str = "StreamPushCount.db", **kwargs):
        cls.db = sqlite3.connect(databaseName, **kwargs)
        cls.cursor = cls.db.cursor()
    
    @classmethod
    def execute(cls, sql: str, parameters=(), result=False):
        cls.cursor.execute(sql, parameters)
        if result:
            return cls.cursor.fetchall()
    
    @classmethod
    def get_tables(cls):
        res = cls.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';",
                          result=True)
        return [x[0] for x in res]
    
    @classmethod
    def get_table(cls, table):
        return cls.execute(f"SELECT * FROM {table};", result=True)
    
    @classmethod
    def create_table(cls, table_name, keys):
        def type_transformer(typ: type):
            if typ == str:
                return "TEXT"
            elif typ == int:
                return "BIGINT"
            return typ
        
        if keys:
            if isinstance(keys, list):
                if isinstance(keys[0], list) and len(keys[0]) == 2:
                    n_keys = {}
                    for i in keys:
                        n_keys[i[0]] = i[1]
                    keys = n_keys
            elif isinstance(keys, dict):
                pass
            else:
                return ValueError("Keys can only be list or dict, but %s given" % type(keys).__name__)
            types = []
            for k, v in keys.items():
                types += [f"{k} {type_transformer(v)} not null"]
            types = ', '.join(types)
            cls.execute(f"CREATE TABLE {table_name}({types});")
            cls.db.commit()
        else:
            raise ValueError("Keys is empty!")
    
    @classmethod
    def drop_table(cls, table):
        cls.execute(f"DROP TABLE {table};")
        cls.db.commit()
    
    @classmethod
    def rename_table(cls, table, new_name):
        cls.execute(f"ALTER TABLE {table} RENAME TO {new_name};")
        cls.db.commit()
    
    @classmethod
    def add_column(cls, table, key, typ):
        cls.execute(f"ALTER TABLE {table} ADD COLUMN {key} {typ};")
        cls.db.commit()
    
    @classmethod
    def init_tables(cls):
        to_tables = {
            "webhooks": {
                "url": str,
                "times": int
            },
            "events"  : {
                "event_type": str,
                "times"     : int
            },
            "received": {
                "data": str,
                "TimeStamp": int
            },
            "counts"  : {
                "name" : str,
                "times": int
            }
        }
        tables = cls.get_tables()
        for t, v in to_tables.items():
            if t not in tables:
                cls.create_table(t, v)
    
    @classmethod
    def close(cls):
        cls.cursor.close()
        cls.db.close()


signal.signal(2, stop)
counter = Counter()
counter.connect(check_same_thread=False)
counter.init_tables()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="简单的转发来自钉钉Stream推送的消息，实现事件回调多播,不受随机网关推送影响")
    parser.add_argument("--app-key", "-k", type=str, help="Stream 模式下的 AppKey")
    parser.add_argument("--app-secret", "-s", type=str, help="Stream 模式下的 AppSecret")
    parser.add_argument("--host", type=str, help="Stream 服务模式下的绑定域名")
    parser.add_argument("--port", "-p", type=int, help="Stream 服务模式下的要绑定的本地端口")
    parser.add_argument("--aes-key", type=str, help="HTTP 模式下的 AesKey")
    parser.add_argument("--token", type=str, help="HTTP 模式下的 Token")
    parser.add_argument("--extra-header", '-H', type=str, help="HTTP 模式下的额外 Header")
    parser.add_argument("--force-nonce", type=str, help="HTTP 模式下重试延迟")
    parser.add_argument("--disable-retry", action='store_true', help="HTTP 模式下不会重试")
    parser.add_argument("--max-retry-times", type=int, help="HTTP 模式下重试次数")
    parser.add_argument("--retry-delay", type=int, help="HTTP 模式下重试延迟")
    args = parser.parse_args()
    if args.app_key:
        AppKey = args.app_key
    if args.app_secret:
        AppSecret = args.app_secret
    if args.host:
        host = args.host
    if args.port:
        port = args.port
    if args.aes_key:
        AesKey = args.aes_key
    if args.token:
        Token = args.token
    if args.extra_header:
        headers = args.extra_header.split(';')
        for h in headers:
            header = h.split('=', 1)
            if len(header) == 2:
                if header[0]:
                    extra_header[header[0]] = header[1]
    if args.force_nonce:
        if (l := len(bytes(args.force_nonce, 'utf8'))) not in [8, 16]:
            logger.warning(
                f"Forced nonce [red bold]{args.force_nonce}[/] is {l}b, not 8b/16b, it may cause some error.")
        force_nonce = args.force_nonce
    if args.disable_retry:
        disable_retry = True
    if args.max_retry_times:
        max_retry_times = args.max_retry_times
    if args.retry_delay:
        retry_delay = args.retry_delay
    if not AppKey or not AppSecret:
        logger.error(f"Error Stream connection config.")
        sys.exit(1)
    if not port and not (args.aes_key or args.token):
        logger.error("At least choose one push type!")
        sys.exit(1)
    if os.path.exists('webhook_urls.txt'):
        with open('webhook_urls.txt', 'r') as f:
            for url in f.readlines():
                url = url.split(' ', 1)
                if len(url) == 1:
                    http_urls.append([url[0], AesKey])
                else:
                    if url[1]:
                        url[1] = url[1].replace('\n', '')
                        if url[1].startswith('ding'):
                            logger.info(f"Added webhook: {url[0]}({url[1]})")
                            http_urls.append([url[0], url[1]])
                        else:
                            logger.error(f"Error webhook AppKey: {url[0]} - ({url[1]})")
                    else:
                        http_urls.append([url[0], AesKey])
                        logger.info(f"Added webhook: {url[0]}")
    logger.info(f"Running with config:\nAppKey:\n> [white bold]{AppKey}[/]\nAppSecret:\n> [white bold]{AppSecret}[/]")
    
    now_date = "Received_" + datetime.datetime.now().strftime("%Y_%m")
    is_exist = counter.execute(f"SELECT * FROM `counts` WHERE name='{now_date}'", result=True)
    all_times = counter.execute("SELECT SUM(times) FROM counts WHERE name LIKE 'Received_%'", result=True)
    if all_times:
        all_times = all_times[0][0]
    websocket_times = [0, is_exist[0][1] if is_exist else 0, all_times]
    
    
    def handle_async_exception(loop, context):
        if err := context.get('exception'):
            logger.error(f"{err.__class__.__name__}: {err}")
    
    
    with ThreadPoolExecutor() as pool:
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(handle_async_exception)
        stream_task = loop.create_task(main_stream())
        if port:
            app = web.Application()
            app.add_routes(
                [web.get('/', handle_websocket), web.post('/v1.0/gateway/connections/open', request_connection)])
            runner = web.AppRunner(app)
            # start_server = websockets.serve(handle_websocket, host, port)
            websocket_task = loop.create_task(main_websocket())
        else:
            websocket_task = None
        pool.submit(main)
        loop.run_forever()
    logger.info("Stopped")
