import os
import sys

os.system('pybabel extract -F resume/babel.cfg -k lazy_gettext -o resume/messages.pot resume/sched')
os.system('pybabel update -i resume/messages.pot -d resume/sched/translations')
os.unlink('resume/messages.pot')