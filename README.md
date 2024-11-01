### 👉 Set Up for `Windows` 

> Install modules via `VENV` (windows) 
```
$ python -m venv mienv
$ mienv\Scripts\activate
$ pip3 install -r requirements2.txt
```
> Set Up Flask Environment
```
python .\app\app.py
```
<br />
### 👉 Set Up for `Unix`, `MacOS` 

> Install modules via `VENV`  

```bash
$ virtualenv mienv
$ source mienv/bin/activate
$ pip3 install -r requirements2.txt
```

<br />

> Set Up Flask Environment


```
$ export FLASK_APP=./app/app.py
$ export FLASK_ENV=development
$ pip3 install -r requirements2.txt
$ flask run
```


<br />

At this point, the app runs at `http://127.0.0.1:5000/`. 

<br />
