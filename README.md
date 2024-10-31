### 👉 Set Up for `Windows` 

> Install modules via `VENV` (windows) 

```
$ python -m venv mienv
$ mienv\Scripts\activate
$ pip3 install -r requirements2.txt
python .\app\app.py
```

<br />

> Set Up Flask Environment

```bash
$ # CMD 
$ set FLASK_APP=run.py
$ set FLASK_ENV=development
$
$ # Powershell
$ $env:FLASK_APP = ".\run.py"
$ $env:FLASK_ENV = "development"
```

<br />

> Start the app

```bash
$ flask run
// OR
$ flask run --cert=adhoc # For HTTPS server
```

At this point, the app runs at `http://127.0.0.1:5000/`. 

<br />