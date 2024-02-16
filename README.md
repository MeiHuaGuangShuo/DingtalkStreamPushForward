# 介绍
简单的转发来自钉钉Stream推送的消息，实现事件回调多播，机器人消息不受随机网关推送影响

# 用法

## 准备
```shell
git clone https://github.com/MeiHuaGuangShuo/DingtalkStreamPushForward.git
cd DingtalkStreamPushForward
pip install -r requirements.txt
```

## Stream(Websocket Only)
```shell
python main.py  --app-key <app-key> --app-secret <app-secret> --host 127.0.0.1 --port 12340
```

## WebHook Only
```shell
python main.py  --app-key <app-key> --app-secret <app-secret> --aes-key <aes-key> --token <token>
```

## Webhook 添加方法
在 `webhook_urls.txt` (自行新建) 中按照如下格式添加，一行一个
```text
WebhookUrl AppKey
```
**注意：程序包含验证(强验证，要求再加密内容完全一致)，若验证不通过则会自动重试，可用通过参数 --disable-retry 关闭重试**

## Stream 链接方法
和钉钉验证一样，POST相同的 `AppKey` `AppSecret` 到 `localhost:12339/v1.0/gateway/connections/open` 来获取地址和URL请求

注意：若 `host` 参数使用的是如 `127.0.0.1` 的地址，返回的也会是 `wss://127.0.0.1:12340?ticket=***`

若需要同时使用Stream和Webhook则同时需要`host`,`port`,`aes-key`,`token`字段完整

