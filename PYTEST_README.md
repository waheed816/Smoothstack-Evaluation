# PYTEST INSTRUCTIONS

## Make Sure that Virtual Environment is Activated

## If not, Activate Virtual Environment:

### - For Mac/Linux, Run the Following Command
```
. venv/bin/activate
```

### - For Windows, Run the Following Command
```
.\venv\Scripts\activate
```

## Run the Following Command to Run All Pyests

```
python -m pytest -v
```

## Run the Following Command to Check Pytest Coverage

```
pytest --cov=app
```

## Run the Following Command to Check Which Lines of Code Were Not Covered in testing

```
pytest --cov=app --cov-report term-missing
```
