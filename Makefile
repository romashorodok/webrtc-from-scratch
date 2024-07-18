
ws:
	uvicorn examples_ws:app --port 9000 --reload

http:
	uvicorn examples_fastapi:app --port 9000 --reload
