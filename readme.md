# Web安全
- 代码层面
- 架构层面
- 运维层面

## 安全问题
- 用户身份被盗用
- 用户密码泄漏
- 用户资料被盗取
- 网站数据库泄漏

### 攻击方式
 xss(Cross Site Scripting) 跨站脚本攻击
原理
程序 + 数据 = 结果

<div>#{count}</div> => countent:hello <script>alert(1)</script>
=> <div>hello</div>   <script>alert(1)</script>

作用：
获取页面数据，获取cookies，劫持前端逻辑，发送请求。。。

分类：
反射性(url直接注入) ：
 1.html节点内容
 <div>#{count}</div>
 防御：
 可以通过转义将脚本显示出来：
 var escapeHtml = function(str){
    str = str.replace(/</g,'&lt;');
    str = str.replace(/>/g,'&gt;');
    return str;
}
ctx.render('index', {posts, comments, from: escapeHtml(ctx.query.from) || ''});
    添加xss方法禁止进入：
    set.ctx('X-XSS-Protection',0)


 2.HTML属性
 <img src="#{img}" alt="">
 <img src="1" onerror="alert(1)" alt="">
 防御：(转义"&quto;")
 var escapeHtmlProperty = function(str){
    if(!str) return '';
    // “”
    str =str.replace(/"/g,'&quto;');
    // ‘’
    str = str.replace(/'/g,'&#39');
    //空格
    return str;
}

 3.JavaScript代码
<script>
    var data ="#{data}";
    var data = "hello";alert(1);""; 
</script>
防御：
    转义"\"或者转化成json
var escapeForJs = function(str){
    if(!str) return '';
    str = str.replace(/\\/g,'\\\\');
    str = str.replace(/"/g,'\\"');
    return str;

}
json.stringfy();

 4.富文本
}
}
- 保留html
- html有xss风险
防御：（按白名单保留部分标签和属性）
var cheerio = require('cheerio');
var whiteList = {
    'img':['src'],
    'font':['size','color'],
    'a':['href']
};
$('*').each(function(index,elem){
    if(!whiteList[elem.name]){
        $(elem).remove();
        return;
    }
    for(var attr in elem.attribs){
       if(whiteList[elem.name].indexOf(attr) === -1){
        $(elem).attr(attr,null);
       }
    }
    });
    return $.html(); 

使用xss过滤：
var xssFilter = function(html){
    if(!html) return '';
    var xss = require('xss');
    var ret = xss(html,{
        whiteList:{
            img:['src'],
            a:['href'],
            font:['size','color']
        },
        onIgnoretag:function(){
            return '';
        }
        });
        return ret;


使用xss过滤：
var xssFilter = function(html){
    if(!html) return '';
    var xss = require('xss');
    var ret = xss(html,{
        whiteList:{
            img:['src'],
            a:['href'],
            font:['size','color']
        },
        onIgnoretag:function(){
            return '';
        }
        });
        return ret;



CSP(Content Security Policy)内容安全策略:
    用于指定哪些内容可执行
    .child-src connect-src default-src
    .font-src frame-src img-src
    .manifest-src media-src object-src
    .script-src style-src worker-src
    
    .<host-source><scheme-source> 'self'
    .'unsafe-inline' 'unsafe-eval' 'none'
    .'nonce-<base64-value>' <hash-source>
    .'strict-dynamic'

ctx.set(`Content-Security-Policy`:`default-src 'self'`);



PHP中防御XSS：
- 内置函数转义
- DOM解析白名单(DOMDocument class)
- 地方库(HTMLPurifier)
- CSP
    header("Content-Security-Policy:script-src 'self'")



浏览器自带防御：
 参数出现在HTML内容或者属性

 存贮性(存贮到DB后读取注入)




### SCRF(Cross Site Request Forgy)
跨域请求伪造
原理：
攻击（前端B）
||
后端 （A）<=====> 前端(A)

危害：
1.利用用户登录态(盗取用户资金)
2.用户不知情(冒充用户发帖)
3.完成业务请求(损坏网站名誉)

防御：
b网站向A网站请求，带A网站Cookies，不妨问A网站前端，referer为B网站
1.禁止第三方网站带cookies
2.same-site属性(禁止访问cookies)
3.不访问A网站前端
    1.在前端页面加入验证信息（图像验证码ccap ）
     var captcha = {};
     var cache = {};
     captache.captcha = async function(ctx,next){
        var ccap = require('ccap');
        var capt = ccap();
        var data = capt.get();
        captcha.setCache(ctx.cookies.get('userId'),data[0]);
        <!-- data[0]; -->
        ctx.body.data[1];
     }
     captcha.setCache = function(uid,data){
        cache[uid]=data;
     }
     captcha.validCache = function(uid,data){
        return cache[uid] === data;
     }
    2.验证码

    3.token(cookie和表单)
        var csrfToken = parseInt(Math.random() * 99999);
        ctx.cookies.set('csrfToken',csrfToken);

4.refer为B网站
    1.验证referer
        var referer = ctx.request.headers.referer;
        <!-- if(referer.indexOf('localhost') === -1){ -->
            if(/^https?:\/\/localhost/.tet(referer)){
            throw new Error('非法请求');
        }
    2. 禁止来自第三方网站的请求

5.PHP防御CSRF
    1.Cookies samesite属性
        header('Set-Cookie:test=123123;SameSite=Lax');
    2.HTTP referer头
        //获取referer头
        $_SERVER(['HTTP_REFERER']);
        // 判断
        if($_SERVER(['HTTP_REFERER'])){
            $isLegal = strpos($_SERVER['HTTP_REFERER'],'http://websercurity.local/') === 0);
            var_dump($isLegal);
        }
    3.token





### cookies
特性：(域名，有效期，路径，http-only,secure(第三方库))
    1.前端数据存贮
    2.后端通过http头设置
    3.请求时通过http头传给后端
    4.前端可读写
    5.遵守同源策略

作用：
    1.存储个性化设置
    2.存储为登陆时用户唯一表示
    3.存储已经登录的凭证
        1.用户ID+签名 
        2.SessionId
    4.存储其他业务数据

策略
    1.签名防篡改46
    2.私有变换(加密)
    3.http-only(防御XSS)
    4.secure(http使用)
    5.same-site(csrf使用，兼容性不好)





### 点击劫持
    防御：
        1.javascript禁止内嵌
            if(top.location != window.location){
                top.location = window.location;
            }
            1.sandbox="allow-script"
        2.X-FRAME-OPTIONS禁止内嵌（设置头部劫持）
        3.其他辅助手段(验证码)

### 传输安全  
    HTTP传输窃听
        浏览器=>代理服务器=>链路=>服务器
    传输链路窃听篡改

    防御：
        TLS(SSL)加密
        使用https证书


### 用户密码 
- 密码的作用
    1.证明用户就是你
    2.密码对比(存储密码 <--对比--> 输入的密码)
    3.泄漏渠道
        数据库被偷
        服务器被入侵
        通讯被窃听
        内部人员泄露数据
        其他网站(撞库)
    4.存储
        1.严禁明文存储
        2.单向变换
        3.变换复杂度
        4.密码复杂度要求
        5.加盐
    5.哈希算法
        明文-密文(--对应)
        雪崩效应(有一个不一样就完全不一样)
        密文-明文  无法反推
        密文固定长度
        常见的哈希算法:md5 sha1 sha256
            md5(明文)=密文
            md5(md5(明文))=密文
            md5(sha1(明文))=密文
            md5(sha256(sha1(明文)))=密文
数据库加密：
 ALTER TABLE `user` ADD COLUMN `salt` varchar(64) NULL DEFAULT "" AFTER `password`;
 明文：
updata user set password='123123',salt=''where id=1;

- 密码的传输
    https
    频率限制
    前端加密意义有限

- 密码的替代方案
- 生物特征密码的问题(指纹，虹膜...)


### sql注入攻击
    关系型数据库
        1.存放结构化数据
        2.可搞笑操作大量数据
        3.方便处理数据之间的关联关系
        4.常见：access/sqlite/mysql/mssql server  

    注入：
        select * from table where id = ${id}
        select * from table where id = 1 or 1 =1;

        select * from user where username = '${data.username}' and password ='${password}'
        select * from user where username = 'LzCrazy' and password ='1' or '1'='1'
        语法
            select * from table where id ="10" and 1=0
            select * from table where id ="10" or 1=1
            select * from table where id ="10" and mid(version(),1,1)=5
            select id 1,2,3 from table
            select * from table union select 1,2,3 from table2
            select * from table where mid(username,1,1)="t"
        危害：
            猜解密码  获取数据 删库删表 拖库

    注入防御：
        关闭错误输入(异常输出其他字符)
        检查数据类型
        对数据进行转义(escape)
        使用参数化查询
        使用ORM(对象关系映射，seqelize)

### NoSQL注入和防御
    检查数据类型
    数据转化
    写完整条件

### 上传问题
    上传文件
    再次访问上传的文件
    上传的文件被当成程序解析
    
    上传问题防御
        1.限制上传后缀
        2.文件类型的检查(不是特别可靠)
        3.文件内容检查(1.读取该文件)
        4.程序输出(通过文件读取给前端)
        5 .权限控制-可写可执行互斥


### 信息泄漏和社会工程学
    1.信息泄漏
        1.泄漏系统敏感信息
        2.泄漏用户敏感信息
        3.泄漏用户密码
    2.泄漏途径
        1.错误信息失控
        2.SQL注入
        3.水平权限控制不当
        4.XSS/CSRF
        ...

    3.OAuth思想
        一切行为由用户授权
        授权行为不泄漏敏感信息
        授权会过期

    4.利用OAuth防止资料泄漏
        敏感资料（派发票据）
        业务（带票据请求）
        用户（登录）
        用户授权都去资料，无授权的资料不可读取，不允许批量获取数据，数据接口可风控审计

### 其他安全问题
    拒绝服务攻击DOS
        1.模拟正常用户（Tcp半链接，http链接，DNS(域名解析)
        2.大量占用服务器资源
        3.大规模分布式解决服务攻击DDOS
            1.流量可达几十道上百G
            2.分布式(肉鸡，代理)
            3.极难防御
    DOS攻击防御
        防火墙
        交换机，路由器
        流量清洗
        高防IP
    DOS攻击预防
        避免重逻辑业务
        快速失败快速返回
        防雪崩机制

    重放攻击
        请求被窃听或记录
        再次发起相同的请求
        产生意外的结果
    后果：
        用户被多次消费
        用户登录态被盗取
        多次抽奖
    防御：
        加密(https)
        时间戳
        token(session)
        nonce(一次性的数字)
        签名              

总结：
    简述XSS的原理
    简述XSS的防御方法
    XSS防御需要注意的点

    CSRF原理是什么
    CSRF的危害是什么
    CSRF如何进行防御

    cookies的作用是什么
    cookies和session的关系
    cookies有哪些特性
    如何删除一个cookies值

    HTTPS是如何保证数据不被窃听
    HTTPS是如何保证不被中间人攻击的
    部署HTTPS的步骤

    SQL注入的原理是什么
    SQL注入有哪些危害
    Node.js中如何防御SQL注入

    文件上传漏洞的原理是什么
    如何防范文件上传文件漏洞

    如何设计用户密码存储
    如何设计登录过程
    如何保证用户密码不被窃听


