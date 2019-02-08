import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, "/var/www/catalog/Udacity-Item-Catalog/vagrant/catalog/")

from application.py import app as application
