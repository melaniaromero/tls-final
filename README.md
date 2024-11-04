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

### 👉 Manual build for `Unix`, `MacOS` 

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
$ flask run
```


<br />

At this point, the app runs at `http://127.0.0.1:5000/`. 

<br />

### 👉 Set up for `Unix`, `MacOS` with scripts 

> change file permissions `.sh`  

```bash
$ chmod 755 install.sh
$ chmod 755 run.sh
```

<br />

> run script with sudo


```
$ sudo ./install.sh
```

> run script


```
$ source ./run.sh
```
<br />

At this point, the app runs at `http://127.0.0.1:5000/`. 

<br />
