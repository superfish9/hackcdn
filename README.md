# hackcdn
寻找CDN背后的真实IP。

## 说明
- 使用猪猪侠的[wydomain2](https://github.com/ring04h/wydomain)进行子域名收集
- 使用第三方库[IPy](https://github.com/autocracy/python-ipy)进行CIDR地址处理
- 根据HTTP响应包长度在给出的地址范围内寻找真实IP
- 使用时可根据情况在URL中带上路径信息/在请求中带上Cookie信息

## 使用

帮助信息

![WX20170712-171055@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-171055%402x.png)

目标网站的域名，使用了CDN

![WX20170712-181255@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181255%402x.png)

收集目标相关信息

![WX20170712-181505@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181505%402x.png)

得到子域名及其IP

![WX20170712-181901@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181901%402x.png)

得到IP段信息，同时发现目标真实IP段

![WX20170712-181521@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181521%402x.png)

在该IP段查找目标网站的真实IP

![WX20170712-181636@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181636%402x.png)

成功发现一个IP

![WX20170712-181651@2x](https://github.com/superfish9/hackcdn/blob/master/doc/WX20170712-181651%402x.png)

Test URL后边的两个数字分别是不特别设置Host头的响应包长度，以及把Host头设置为目标域名时的响应包长度（考虑到有些网站的真实IP所在主机为反向代理，它们会根据Host头转发到后段负载主机）。如果前者是0而后者长度正确，则应在本地配置hosts后通过域名访问网站。