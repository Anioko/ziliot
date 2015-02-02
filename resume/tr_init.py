import os
import sys

if len(sys.argv) != 2:
    print "usage: tr_init <language-code>"
    sys.exit(1)
os.system('pybabel extract -F resume/babel.cfg -k lazy_gettext -o resume/messages.pot resume/sched')
os.system('pybabel init -i resume/messages.pot -d resume/sched/translations -l ' + sys.argv[1])
os.unlink('resume/messages.pot')