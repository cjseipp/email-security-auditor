import unittest
from audit_engine import audit,txt_strings
class Fake:
 def resolve(self,name,kind,lifetime=6):
  class Answer:
   def __init__(self,v):self.v=v
   def to_text(self):return self.v
  if kind=='TXT' and name=='example.org':return [Answer('"v=spf1 include:_spf.example.org -all"')]
  if kind=='TXT' and name=='_dmarc.example.org':return [Answer('"v=DMARC1; p=none; rua=mailto:reports@example.org"')]
  return [Answer('sample-record')]
class Tests(unittest.TestCase):
 def test_spf(self):self.assertEqual('Info',next(x['severity'] for x in audit('example.org',Fake())['findings'] if x['control']=='SPF'))
 def test_dmarc(self):self.assertIn('p=none',next(x['observation'] for x in audit('example.org',Fake())['findings'] if x['control']=='DMARC'))
 def test_invalid(self):
  with self.assertRaises(ValueError):audit('https://example.org')
 def test_split_txt(self):self.assertEqual(['v=spf1 -all'],txt_strings(['"v=spf1 " "-all"']))
if __name__=='__main__':unittest.main()
