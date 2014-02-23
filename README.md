FLOOD YOUR SHIT
=====

这是我在学习TCP相关协议时写的一个小工具，目的仅是为了更加了解TCP的底层结构。

#### 测试

1. 先搭起一个本地web服务器`python -m SimpleHTTPServer 8888`;
2. 运行本程序`sudo ./syn_flood.py local_ip 8888`，这里的local_ip要换成本机外网卡的一个IP，localhost或127.0.0.1都没用，不知为什么;
3. 打开浏览器，访问`localhost:8888`，浏览器应该一直停留在connecting的状态。

#### 注意
1. 攻击的机器和被攻击的机器一定要在同一局域网里，不然被攻击的机器根本收不到发出的sync包，猜测可能包在路由器那端被吃掉了，不知你有什么好解释没？对，问的就是你！
2. 只在Linux下测试过，别的系统应该不行。
