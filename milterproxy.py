#!/usr/local/bin/python
# -*- coding: utf-8 -*-
'''milterproxy

output sendmail/proxy remoteaddr 動作モードを作る？
milter.py の Milter を上と共通に

testsmtpproxy.py は import milterproxy ; TestMilter(Milter)
milter.py は import milterproxy ; mil = Milter() .. 呼び方変える
    (option でスルー時も sendmail 使用? proxy 専用?)

'''

import sys, os
import traceback
import re
import sre_constants
import time
import datetime
import logging
import random
import subprocess
import threading
import smtpd, asyncore, socket
import email.Parser
import email.header

random.seed()
APP_NAME = os.path.basename(sys.argv[0]).split('.')[0]
BASE_DIR = os.path.dirname(__file__)
LOGFILE = '%s/%s.log' % (BASE_DIR, APP_NAME)
SENDMAIL = ['/usr/sbin/sendmail', '-i']
SPAMDROP = ['spamdrop@hoge.fuga']
MAILROOT = 'root@hoge.fuga'

class Milter(object):
  def __init__(self, name, basedir, eid, server, prx, headerflg=None):
    self.name = name
    self.basedir = basedir
    self.eid = eid
    self.server = server
    self.prx = prx
    self.headerflg = headerflg if headerflg else 'X-SPAM-BLOCK-Flag'
    self.headerver = ('X-SPAM-FILTER', 'Filter 2.0 powered by Python')
    self.logger = logging.getLogger('%s: %s' % (name, eid))

  def getdt(self):
    self.dt = datetime.datetime.now()
    pt = '%s/%s' % (self.basedir, self.name)
    if not os.path.exists(pt):
      os.mkdir(pt)
    for n, d in ((4, self.dt.year), (2, self.dt.month), (2, self.dt.day)):
      pt = '%s/%0*d' % (pt, n, d)
      if not os.path.exists(pt):
        os.mkdir(pt)
    self.fname = '%s/%s.%06d.%08d.%s.log' % (
      pt, datetime.datetime.strftime(self.dt, '%Y%m%d.%H%M%S'),
      self.dt.microsecond, os.getpid(), self.eid)
    self.logger.info(self.fname)
    ofp = open(self.fname, 'a')
    ofp.write(self.s)
    ofp.close()

  def process_check(self):
    self.msg.add_header(*self.headerver)
    return True #False

  def check(self, data):
    self.s = data
    self.getdt()
    self.msg = email.Parser.Parser().parsestr(self.s)
    self.mid = self.msg['Message-Id']
    self.snd = self.msg['From']
    self.rcp = self.msg['To']
    self.sbj = self.msg['Subject']
    self.rcv = self.msg.get_all('Received')
    self.logger.debug('--\n%s\n--\n' % '\n'.join(self.rcv))
    self.flg = self.process_check()
    self.logger.info(
      'spam=%s, size=%d, id=[%s], from=[%s], to=[%s], eid=[%s]' % (
        self.flg, len(self.s), self.mid, self.snd, self.rcp, self.eid))
    self.msg.add_header(self.headerflg, '%s' % self.flg)
    if self.flg:
      f = self.msg.replace_header if self.sbj else self.msg.add_header
      f('Subject', '[SPAM?to:%s] %s' % (self.rcp, self.sbj))
    return self.flg

  def sendm(self, mailfrom, rcpttos, buf):
    try:
      result = False
      cmdopt = SENDMAIL + ['-f', mailfrom, '--'] + rcpttos
      p = subprocess.Popen(cmdopt, shell=False, bufsize=4096,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True)
      (si, so, se) = (p.stdin, p.stdout, p.stderr)
      # so.read()
      # so.readline()
      si.write(buf)
      si.flush()
      self.logger.debug('sendm [%s]' % ' '.join(cmdopt))
      result = True
    except (OSError, ValueError), e:
      e_type, e_value, e_tb = sys.exc_info()
      tb = ['Traceback (most recent call last):']
      tb += traceback.format_tb(e_tb)
      tb.append('%s: %s' % (e_type.__name__, e_value))
      self.logger.error('sendm subprocess.Popen\n%s' % (''.join(tb)))
    finally:
      si.close()
      so.close()
      se.close()
      p = None
    return result

  def __call__(self, mailfrom, rcpttos, data):
    try:
      # output -> connect to _remoteaddr
      tgt = rcpttos
      if self.check(data):
        tgt = SPAMDROP
      rfsd = self.server._deliver(mailfrom, rcpttos, self.msg.as_string())
      del self.msg
      return True if (rfsd == None or rfsd == {}) else False
    except:
      e_type, e_value, e_tb = sys.exc_info()
      tb = ['Traceback (most recent call last):']
      tb += traceback.format_tb(e_tb)
      tb.append('%s: %s' % (e_type.__name__, e_value))
      self.logger.error('process_message (proxy?)\n%s' % ''.join(tb))
      return False

class S25RMilter(Milter):
  def __init__(self, name, basedir, eid, server, prx):
    Milter.__init__(self, name, basedir, eid, server, prx)

  def loadlist(self, md, fnl):
    class atr(object):
      pass
    setattr(self, md, atr())
    for fn in fnl:
      lst = []
      pt = '%s/rules/%s_%s.rules' % (self.basedir, md, fn)
      if os.path.exists(pt):
        ifp = open(pt)
        for line in ifp.readlines():
          k = line.rstrip('\r\n')
          if k:
            lst.append(k.decode('utf-8'))
        ifp.close()
      setattr(getattr(self, md), fn, lst)

  def getdt(self):
    Milter.getdt(self)
    self.loadlist('deny', ['head', 'head_partial', 'head_regexp',
      'body', 'body_partial', 'body_regexp'])
    self.loadlist('accept', ['head_regexp', 'body_regexp'])

  def guess_dec(self, u, c):
    if not isinstance(u, unicode):
      self.logger.debug('[]%s' % ''.join(('%02x' % ord(b)) for b in u[:4]))
      code = ['utf-8', 'euc-jp', 'cp932', 'iso-2022-jp', 'latin-1', 'ascii']
      for cd in ([c] if c else []) + code:
        try:
          u = u.decode(cd)
          break
        except (UnicodeDecodeError, LookupError):
          continue
      else:
        u = u.decode('latin-1', 'replace')
    return u

  def dec_mime_header(self, s):
    lst = []
    if s is None:
      return u''
    for l in s.split('\n'):
      try:
        for d in email.header.decode_header(l):
          lst.append(self.guess_dec(d[0], d[1]))
      except email.errors.HeaderParseError:
        continue
    return u''.join(lst) #.encode('utf-8')

  def escapeword(self, word):
    lst = []
    for c in word:
      if c in r'?![]()^$.': #'?![]()^=$.'
        lst.append(u'\\')
      lst.append(c)
    return u''.join(lst)

  def isc(self, hb, text, words):
    r = re.compile(r'([\@\.\/\<\>\(\)]+)', re.I)
    t = r.sub(u' ', text)
    for word in words:
      w = self.escapeword(word)
      if re.search(r'(^%s$)' % w, text, re.I) or \
        re.search(r'(^%s\s)' % w, text, re.I) or \
        re.search(r'(\s%s$)' % w, text, re.I) or \
        re.search(r'(\s%s\s)' % w, text, re.I):
        return [u'%s contains [%s]' % (hb, word)]
    return []

  def isc_partial(self, hb, text, words):
    for word in words:
      w = self.escapeword(word)
      if re.search(w, text, re.I):
        return [u'%s contains partial [%s]' % (hb, word)]
    return []

  def isc_regexp(self, hb, text, words):
    for word in words:
      try:
        if re.search(word, text, re.I):
          return [u"%s contains regexp '%s'" % (hb, word)]
      except sre_constants.error, e:
        msg = 'From: %s\nTo: %s\nSubject: %s\n\n%s' % (
          MAILROOT, MAILROOT, 'Regexp Error: %s' % APP_NAME,
          '%s\n%s\n' % (e, word.encode('utf-8')))
        self.sendm(MAILROOT, [MAILROOT], msg)
    return []

  def spam_ip_check(self, val, key):
    if not re.search(r'\.', val, re.I):
      return ['%s wrong from [%s] not [%s]' % (key, val, r'\.')]
    s25r = [
      (r'(unknown)', '%s word [%s] [%s]'),
      (r'^([0-9\.]+)$', '%s as [%s] [%s]'),
      (r'^\[([0-9\.]+)\]$', '%s [%s] [%s]'),
      (r'([0-9]+[x\-\.]+[0-9]+[x\-\.]+[0-9]+)', '%s IP like [%s] [%s]'),
      (r'^[^\.]*([0-9]{5,})', '%s IP like [%s] [%s]'),
      (r'^[^\.]*([0-9a-fA-F]{8,})', '%s IP like [%s] [%s]'),
      (r'.*(ppp|dsl|sdl|dhcp).*\.[^\.]+\.[^\.]+$', '%s IP like [%s] [%s]'),
      (r'.*(host|catv|cable|dial).*\.[^\.]+\.[^\.]+$', '%s IP like [%s] [%s]'),
      (r'.*(static|dynamic).*\.[^\.]+\.[^\.]+$', '%s IP like [%s] [%s]'),
      (r'.*(nat|cdma)\-.*\.[^\.]+\.[^\.]+$', '%s IP like [%s] [%s]'),
      (r'^p([0-9]+)\-ip', '%s IP like [%s] [%s] (p{N}-ip) marunouchi...')]
    for sr in s25r:
      if re.search(sr[0], val, re.I):
        return [sr[1] % (key, val, sr[0])]
    return []

  def entity_received0_check(self, rcv0): #hel, hos, rip, fgd):
    (hel, hos) = None, None
    r0 = re.compile(r'(\x0D)', re.I).sub('', rcv0)
    r0 = re.compile(r'(\x0A|[\s]+)', re.I).sub(' ', r0)
    m = re.compile(r'from ([^\s]+) \(([^\[\s]*)', re.I).search(r0)
    if m:
      (hel, hos) = m.groups()
    spam = self.spam_ip_check(hel, 'received0')
    if len(spam) and (hel and hel == hos):
      return ['AttachedMailHeaderLikesAspam [%s]' % spam]
    return []

  def entity_check(self, entity, depth):
    lst = []
    cs = entity.get_charsets()
    self.logger.debug('[]%*s(depth: %d, %s, %d)' % (
      depth + 1, ' ', depth, entity.get_content_type(), len(cs) - 1))
    if entity.is_multipart():
      for i, c in enumerate(cs[1:]):
        self.logger.debug('[]%*s(depth: %d, e: %d, charset: %s)' % (
          depth + 1, ' ', depth, i, c))
        try:
          lst += self.entity_check(entity.get_payload(i), depth + 1)
        except IndexError:
          pass
    else:
      if entity.get_content_maintype() == 'text':
        c = entity.get_content_charset() # cs[0]
        self.logger.debug('[]%*s(depth: %d, charset: %s)' % (
          depth + 1, ' ', depth, c))
        u = self.guess_dec(entity.get_payload(None, True), c)
        self.logger.debug('\n'.join(
          ('[]%s' % l) for l in u.encode('utf-8', 'replace').split('\n')))
        e = email.Parser.Parser().parsestr(u.encode('iso-2022-jp', 'replace'))
        if e.is_multipart():
          lst += self.entity_check(e, depth + 1)
        else:
          lst.append(u)
    self.logger.debug('[]%*s--------(depth %d)' % (depth + 1, ' ', depth))
    # 仮
    # (depth > 0 のときだけ entity_received0_check 呼ぶ text ? head ?)
    # 各 part 毎に file 出力 ?
    return lst # unicode

  def process_check(self):
    (chel, chos, crip, cfgd) = ('unknown', 'unknown', '0.0.0.0', '')
    ceid = self.msg['X-SPAM-BLOCK-Id']
    if ceid:
      (chel, chos, crip, cfgd) = ceid.split(' ', 2)[1].split(',', 4)
    self.logger.debug('chel=%s, chos=%s, crip=%s, cfgd=%s' % (
      chel, chos, crip, cfgd))

    (crvn, crvi) = ('', '')
    try:
      crvn = socket.gethostbyaddr(crip)[0]
      crvi = [ai[4][0] for ai in socket.getaddrinfo(
        crvn, 25, socket.AF_INET, socket.SOCK_STREAM, 6)]
    except (socket.error, socket.herror, socket.gaierror, socket.timeout), e:
      pass # self.logger.debug('error gethostbyaddr/gethostbyname')
    self.logger.debug('crvn=%s, crvi=%s' % (crvn, crvi))

    # self_rcved_rec = self.entity_received0_check(self.rcv[0]) # 仮
    # self.logger.debug('srr=%s\n' % self_rcved_rec.encode('utf-8', 'replace'))

    sndr = self.dec_mime_header(self.snd)
    rcpt = self.dec_mime_header(self.rcp)
    subj = self.dec_mime_header(self.sbj)
    whole_body = u'\n'.join(self.entity_check(self.msg, 0))
    self.logger.debug('body=%s\n' % whole_body.encode('utf-8', 'replace'))

    (white, spam) = ([], [])
    if chos == 'localhost' and crip == '127.0.0.1' and not len(white):
      white += ['localhost [127.0.0.1]']
    if sndr and not len(white):
      white += self.isc_regexp('FROM', sndr, self.accept.head_regexp)
    if rcpt and not len(white):
      white += self.isc_regexp('TO', rcpt, self.accept.head_regexp)
    if subj and not len(white):
      white += self.isc_regexp('SUBJECT', subj, self.accept.head_regexp)
    if subj and not len(spam):
      spam += self.isc('SUBJECT', subj, self.deny.head)
      if not len(spam):
        spam += self.isc_partial('SUBJECT', subj, self.deny.head_partial)
        if not len(spam):
          spam += self.isc_regexp('SUBJECT', subj, self.deny.head_regexp)

    # tv_sec, tv_usec, tid(sec_usec_port_iaddr), envelope_rcpts
    # headers, self_rcved_rec(by ... 最初に見つかったもの)

    # helohost, hostname, port, iaddr, irev, irip
    # chel,     chos,     int,  crip,  crvn, crvi
    # Received: from chel (chos [crip] (cfgd)) by ...
    #  chos != crvn or chel ? (cfgd)
    #  crvn == unknown or crvn ... crip == myip ? white
    #  crvi == None or crvi != crip
    if not len(white) and not len(spam):
      if not len(spam):
        spam += self.spam_ip_check(chel, 'helohost')
        if not len(spam):
          spam += self.spam_ip_check(chos, 'hostname')
          if not len(spam):
            spam += self.spam_ip_check(crvn, 'reverse name')
      if not len(spam):
        if not len(crvi):
          spam += ['reverse name re-lookup fail [%s]' % crvn]
      if len(spam):
        spam = ['RECEIVED contains '] + spam

    if len(whole_body):
      if not len(white):
        white += self.isc_regexp('BODY', whole_body, self.accept.body_regexp)
      if not len(spam):
        spam += self.isc('BODY', whole_body, self.deny.body)
        if not len(spam):
          spam += self.isc_partial('BODY', whole_body, self.deny.body_partial)
          if not len(spam):
            spam += self.isc_regexp('BODY', whole_body, self.deny.body_regexp)

    self.msg.add_header(*self.headerver)
    if not len(spam):
      if not len(white):
        self.msg.add_header('X-NON-SPAM', 'Through because normal.')
        pass # NORMAL
      else:
        self.msg.add_header('X-NON-SPAM',
          'Through because white. [%s]' % u','.join(white))
        pass # WHITE
    else:
      if not len(white):
        self.msg.add_header('X-SPAM-BLOCK',
          'It seems to be a spam. [%s]' % u','.join(spam))
        return True # SPAM
      else:
        self.msg.add_header('X-NON-SPAM',
          'Through because white. [%s] with spam [%s]' % (
            u','.join(white), u','.join(spam)))
        pass # WHITE not SPAM
    return False

  def __call__(self, mailfrom, rcpttos, data):
    try:
      # output -> connect to _remoteaddr
      tgt = rcpttos
      if self.check(data):
        if True: # spamdrop or through
          if True: # break or falldown
            # skip to connect to _remoteaddr
            res = self.sendm(mailfrom, SPAMDROP, self.msg.as_string())
            del self.msg
            return res
          else:
            tgt = SPAMDROP
      rfsd = self.server._deliver(mailfrom, rcpttos, self.msg.as_string())
      del self.msg
      return True if (rfsd == None or rfsd == {}) else False
    except:
      e_type, e_value, e_tb = sys.exc_info()
      tb = ['Traceback (most recent call last):']
      tb += traceback.format_tb(e_tb)
      tb.append('%s: %s' % (e_type.__name__, e_value))
      self.logger.error('process_message (proxy?)\n%s' % ''.join(tb))
      return False

class MilterProxy(smtpd.PureProxy):
  '''override
  '''
  def __init__(self, name, basedir, localaddr, remoteaddr, milter):
    smtpd.PureProxy.__init__(self, localaddr, remoteaddr)
    self.name = name
    self.basedir = basedir
    self.milter = milter
    logging.info('%s start %s' % (self.name, self.basedir))
    self.logger = logging.getLogger(name)
    self.rcvpat = re.compile(
      'from\s+([^\s]+)\s+\(([^\s]*)\s*\[(\d+\.\d+\.\d+\.\d+)\]\s*(.*)\)\s+by',
      re.I)

  def handle_accept(self):
    '''override
    '''
    conn, addr = self.accept()
    self.logger.debug('incomming connection from %s:%d' % (addr))
    channel = MilterProxySMTPChannel(self, conn, addr)

  def process_message(self, peer, mailfrom, rcpttos, data):
    '''This function should return None, for a normal `250 Ok' response;
    otherwise it returns the desired response string in RFC 821 format.
    '''
    eid = data.split('\n')[0].split(' ')[1] # 'X-SPAM-BLOCK-Id: HEX\n'
    mil = self.milter(self.name, self.basedir, eid, self, smtpd.PureProxy)
    if not mil(mailfrom, rcpttos, data):
      return '451 error'

  def is_valid_recipient(self, address):
    return True # False

class MilterProxySMTPChannel(smtpd.SMTPChannel):
  '''created one channel for one connection
  '''
  def __init__(self, server, conn, addr):
    smtpd.SMTPChannel.__init__(self, server, conn, addr)

  def makeeid(self, server, peer, data):
    try:
      (phel, phos, prip, pfgd) = ('unknown', 'unknown', peer[0], '')
      prcv = []
      line = smtpd.EMPTYSTRING.join(data).split('\r\n')
      if len(line) > 0 and line[0].split(' ', 1)[0] == 'Received:':
        prcv.append(line[0])
        i = 1
        while(len(line) > i and len(line[i]) > 0 and (
          line[i][0] == ' ' or line[i][0] == '\t')):
          prcv.append(line[i])
          i += 1
        m = re.search(server.rcvpat, ''.join(prcv))
        if m:
          (phel, phos, prip, pfgd) = m.groups()
      pirip = reduce(
        lambda x, y: int(x) * 256 + int(y), re.findall('\d+', prip), 0)
    except:
      e_type, e_value, e_tb = sys.exc_info()
      tb = ['Traceback (most recent call last):']
      tb += traceback.format_tb(e_tb)
      tb.append('%s: %s' % (e_type.__name__, e_value))
      logging.getLogger('DEBUGSTREAM').error('peer ip\n%s' % (''.join(tb)))
      pirip = 0
    tt = time.time()
    eid = '%X.%08X.%06X.%08X' % (
      int(tt * 1000000L), os.getpid(), random.randint(0, 1000000), int(pirip))
    tstr = time.strftime('%%a, %%d %%b %%Y %%H:%%M:%%S +%04d (%%Z)' % (
      time.timezone * 100 / -3600), time.localtime(tt))
    return ((phel, phos, prip, pfgd), eid, tstr)

  def found_terminator(self):
    '''override
    '''
    if self._SMTPChannel__state == self.DATA:
      server = self._SMTPChannel__server
      peer = self._SMTPChannel__peer
      (pre, eid, tstr) = self.makeeid(server, peer, self._SMTPChannel__line)
      revnm = None
      revip = None
      try:
        revnm = socket.gethostbyaddr(peer[0])[0]
        revip = [ai[4][0] for ai in socket.getaddrinfo(
          revnm, 25, socket.AF_INET, socket.SOCK_STREAM, 6)]
      except (socket.error, socket.herror, socket.gaierror, socket.timeout), e:
        logging.getLogger('DEBUGSTREAM: %s' % eid).debug('error gethostbyaddr')
      rcv = '%s\n\t%s\n\t%s\n\t%s\n' % (
        'Received: from %s (%s[%s])' % (
          self._SMTPChannel__greeting, '%s ' % revnm if revnm else '', peer[0]),
        'by %s (%s, port %s) with ESMTP id %s' % (
          self._SMTPChannel__fqdn, server.name, server._localaddr[1], eid),
        'for <%s>;' % repr(self._SMTPChannel__rcpttos),
        tstr)
      self._SMTPChannel__line.insert(0, rcv)
      self._SMTPChannel__line.insert(0, 'X-SPAM-BLOCK-Id: %s %s,%s,%s,%s\n' % (
        eid, pre[0], pre[1], pre[2], pre[3]))
    return smtpd.SMTPChannel.found_terminator(self)

  def smtp_HOGE(self, arg):
    '''command
    '''
    self.push('Test print HOGE arg=%s' % arg)

  def smtp_RCPT(self, arg):
    if not self._SMTPChannel__mailfrom:
      self.push('503 Error: need MAIL command')
      return
    address = self._SMTPChannel__getaddr('TO:', arg)
    if not address:
      self.push('501 Syntax: RCPT TO: <address>')
      return
    if self._SMTPChannel__server.is_valid_recipient(address):
      self._SMTPChannel__rcpttos.append(address)
      self.push('250 Ok')
    else:
      self.push('550 No such user here')

class DevDebugStream(smtpd.Devnull):
  def write(self, msg):
    if msg != ' ' and msg != '\n':
      logging.getLogger('DEBUGSTREAM').debug(msg)
  def flush(self):
    pass

if __name__ == '__main__':
  # sys.path.append(os.path.dirname(__file__))
  # sys.path.append(os.path.join(os.path.dirname(__file__), 'application'))
  fmt = '%(asctime)s [%(name)-8s:%(process)8s] %(levelname)-8s: %(message)s'
  logging.basicConfig(level=logging.DEBUG,
    format=fmt, datefmt='%Y-%m-%d %H:%M:%S',
    filename=LOGFILE, filemode='a')
  ''' '''
  console = logging.StreamHandler()
  console.setLevel(logging.DEBUG)#INFO)
  console.setFormatter(logging.Formatter(fmt))
  logging.getLogger('').addHandler(console)
  ''' '''

  smtpd.DEBUGSTREAM = DevDebugStream()
  s = MilterProxy(APP_NAME, BASE_DIR,
    ('localhost', 8025), ('localhost', 10024), S25RMilter)
  def run():
    try:
      asyncore.loop()
    except KeyboardInterrupt:
      pass
  threading.Thread(None, run).start()
  sys.stderr.write('stopped %s\n' % APP_NAME)
