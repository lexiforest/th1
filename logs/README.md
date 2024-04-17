## How to capture pcap and http2 logs for new browser

1. Install tcpdump and nghttp2, for example, on macOS:

        brew install tcpdump nghttp2

2. Find the interface and local IP you need to listen to:

        # on macOS
        ifconfig
        # on Linux
        ip a s

3. Start tcpdump and nghttpd, replace the browser_name and interface

        nghttpd -v 8443 capture/ssl/server.key capture/ssl/server.crt 2> /dev/null > logs/<BROWSER_NAME>.log

        # note sudo
        sudo tcpdump -n -i <INTERFACE> -s 0 -w - -U '(tcp src portrange 0-65535 and tcp dst port 8443) or (tcp dst portrange 0-65535 and tcp src port 8443)' > logs/<BROWSER_NAME>.pcap

4. Use your browser to navigate to `https://LOCAL_IP:8443`, click "Advanced" and ignore any ssl error and proceed.

5. There shoud be a new log and pcap file in `logs/`.

6. Open a new tab and navigate to https://tls.browserleaks.com/json

7. Copy the content and save as `logs/<BROWSER_NAME>.json`

8. Run `pip install -e .` and `python logs/parse.py <BROWSER_NAME>`, if no exception raised, there should be a file called `signatures/new.yaml`

9. Commit all the files and open a PR.


## 如何抓取一个新的浏览器的 pcap 文件和 http2 日志

1. 安装 tcpdump 和 nghttp2, 比如, 在 macOS:

        brew install tcpdump nghttp2

2. 找到要监听的网卡名称和本地 IP:

        # on macOS
        ifconfig
        # on Linux
        ip a s

3. 打开 tcpdump 和 nghttpd, 替换到下面的 browser_name 和 interface

        nghttpd -v 8443 capture/ssl/server.key capture/ssl/server.crt 2> /dev/null > logs/<BROWSER_NAME>.log

        # note sudo
        sudo tcpdump -n -i <INTERFACE> -s 0 -w - -U 'tcp dst port 8443 or tcp src port 8443' > logs/<BROWSER_NAME>.pcap

4. 用浏览器打开 `https://LOCAL_IP:8443`, 点击 "高级选项" 然后忽略 SSL 错误并前往。

5. 这时候在 `logs/` 应该有一个新的 pcap 和 log 文件

6. 在新标签页打开 https://tls.browserleaks.com/json

7. 复制并保存成 `logs/<BROWSER_NAME>.json`

8. `pip install -e .` 然后 `python logs/parse.py --browser <BROWSER_NAME> --port 8443`, 没有异常的话，应该生成 `signatures/new.yaml`

9. 添加并提交所有文件，然后开一个 PR。
