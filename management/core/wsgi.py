import os
import sys

# Allow running this file directly as well as via gunicorn - both need
# management/ on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.daemon import app
from core import utils

app.logger.addHandler(utils.create_syslog_handler())

if __name__ == "__main__":
	app.run(port=10222)
