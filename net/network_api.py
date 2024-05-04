import threading
from apiflask import APIFlask


app = APIFlask(__name__)

def run_network_api():
    t = threading.Thread(target=app.run, port=2000)

def stop_network_api():
    app.stop()

if __name__ == "__main__":
    run_network_api()