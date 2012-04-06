#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''milter.py
'''

import sys, os
import traceback
import time
import datetime
import logging
import milterproxy

APP_NAME = os.path.basename(sys.argv[0]).split('.')[0]
BASE_DIR = os.path.dirname(__file__) # '/var/mail/filter'
LOGFILE = '%s/%s.log' % (BASE_DIR, APP_NAME)

class PyMilter(milterproxy.Milter):
  def __init__(self, name, basedir, eid):
    milterproxy.Milter.__init__(self,
      name, basedir, eid, None, None, 'X-SPAM-DROP-Flag')

  def process_check(self):
    f = self.msg['X-SPAM-BLOCK-Flag'] # 'True' or 'False' or None
    if f == 'True':
      return True
    f = self.msg['X-Spam-Flag'] # 'YES' or 'NO' or None
    if f == 'YES':
      return True
    return False

  def __call__(self, mailfrom, rcpttos, data):
    try:
      if self.check(data):
        return self.sendm(mailfrom, milterproxy.SPAMDROP, self.msg.as_string())
      else:
        return self.sendm(mailfrom, rcpttos, self.msg.as_string())
    except:
      e_type, e_value, e_tb = sys.exc_info()
      tb = ['Traceback (most recent call last):']
      tb += traceback.format_tb(e_tb)
      tb.append('%s: %s' % (e_type.__name__, e_value))
      self.logger.error('milter (sendmail?)\n%s' % ''.join(tb))
      return False

if __name__ == '__main__':
  # sys.path.append(os.path.dirname(__file__))
  # sys.path.append(os.path.join(os.path.dirname(__file__), 'application'))
  fmt = '%(asctime)s [%(name)-8s:%(process)8s] %(levelname)-8s: %(message)s'
  logging.basicConfig(level=logging.DEBUG,
    format=fmt, datefmt='%Y-%m-%d %H:%M:%S',
    filename=LOGFILE, filemode='a')
  '''
  console = logging.StreamHandler()
  console.setLevel(logging.INFO)
  console.setFormatter(logging.Formatter(fmt))
  logging.getLogger('').addHandler(console)
  '''

  logging.info('%s start %s' % (APP_NAME, BASE_DIR))
  '''
  random.seed()
  time.sleep(random.randint(0,1))
  self.logger.debug('TEST1')
  time.sleep(random.randint(0,1))
  self.logger.info('TEST1')
  time.sleep(random.randint(0,1))
  self.logger.warning('TEST1')
  time.sleep(random.randint(0,1))
  self.logger.error('TEST1')
  '''

  pymil = PyMilter(APP_NAME, BASE_DIR, '0 localhost,localhost,127.0.0.1,')
  if not pymil(sys.argv[2], sys.argv[4:], sys.stdin.read()):
    sys.stderr.write('error %s\n' % APP_NAME)
