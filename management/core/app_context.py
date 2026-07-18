# Shared singletons. Both daemon.py and every view module import these from
# here (never from daemon.py itself) so there's no circular import between
# the app assembly point and the route modules it registers.

from core import utils
from auth import auth
from mail.mailconfig import initialize_database

env = utils.load_environment()

# Ensure DB tables exist and database file is 660 (so -shm inherits correctly).
initialize_database(env)

auth_service = auth.AuthService()
